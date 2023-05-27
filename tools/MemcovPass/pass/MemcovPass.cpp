#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/CodeGen/RegAllocRegistry.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/ProfileData/InstrProf.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"

#include "pass/MemcovPass.h"
#include "llvm/ADT/DenseSet.h"

using namespace llvm;

#define DEBUG_TYPE "memcov"

static cl::opt<bool> ClDumpIRs(
    "dump-ir",
    cl::desc(
        "Dump IRs before and after instrumenting callbacks (for debugging)"),
    cl::init(false));

static cl::opt<bool> ClBuileKernel("ssb-kernel",
                                   cl::desc("Build a Linux kernel"),
                                   cl::init(false));

STATISTIC(NumInstrumentedReads, "Number of instrumented reads");
STATISTIC(NumInstrumentedWrites, "Number of instrumented writes");
STATISTIC(NumAccessesWithBadSize, "Number of accesses with bad size");

namespace {

/*
 *Pass Implementation
 */
struct Memcov {
  bool instrumentFunction(Function &F, const TargetLibraryInfo &TLI);

private:
  void initialize(Module &M);
  bool instrumentAll(Function &F, const TargetLibraryInfo &TLI);
  bool instrumentLoadOrStore(Instruction *I, const DataLayout &DL);
  bool addrPointsToConstantData(Value *Addr);
  void chooseInstructionsToInstrument(SmallVectorImpl<Instruction *> &Local,
                                      SmallVectorImpl<Instruction *> &All,
                                      const DataLayout &DL);
  int getMemoryAccessFuncIndex(Value *Addr, const DataLayout &DL);
  bool isInterestingLoadStore(Instruction *I);
  bool isBUG(Instruction *I);
  void SetNoSanitizeMetadata(Instruction *I) {
    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(I->getContext(), None));
  }
  /* Collected instructions */
  SmallVector<Instruction *, 8> AllLoadsAndStores;
  SmallVector<Instruction *, 8> LocalLoadsAndStores;
  /* Callbacks */
  // Accesses sizes are powers of two: 1, 2, 4, 8, 16.
  static const size_t kNumberOfAccessSizes = 5;
  enum MemoryModel { TSO, PSO, kNumberOfMemoryModels };
  MemoryModel TargetMemoryModel;
  FunctionCallee MemcovLoad[kNumberOfAccessSizes];
  FunctionCallee MemcovStore[kNumberOfAccessSizes];
  enum Architecture { X86_64, Aarch64, kNumberOfArchitectures };
  Architecture TargetArchitecture;
};

// Do not instrument known races/"benign races" that come from compiler
// instrumentatin. The user has no way of suppressing them.
static bool shouldInstrumentReadWriteFromAddress(const Module *M, Value *Addr) {
  // Peel off GEPs and BitCasts.
  Addr = Addr->stripInBoundsOffsets();

  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Addr)) {
    if (GV->hasSection()) {
      StringRef SectionName = GV->getSection();
      // Check if the global is in the PGO counters section.
      auto OF = Triple(M->getTargetTriple()).getObjectFormat();
      if (SectionName.endswith(
              getInstrProfSectionName(IPSK_cnts, OF, /*AddSegmentInfo=*/false)))
        return false;
    }

    // Check if the global is private gcov data.
    if (GV->getName().startswith("__llvm_gcov") ||
        GV->getName().startswith("__llvm_gcda"))
      return false;
  }

  // Do not instrument acesses from different address spaces; we cannot deal
  // with them.
  if (Addr) {
    Type *PtrTy = cast<PointerType>(Addr->getType()->getScalarType());
    if (PtrTy->getPointerAddressSpace() != 0)
      return false;
  }

  return true;
}

bool Memcov::addrPointsToConstantData(Value *Addr) {
  // If this is a GEP, just analyze its pointer operand.
  if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(Addr))
    Addr = GEP->getPointerOperand();

  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Addr)) {
    if (GV->isConstant()) {
      // Reads from constant globals can not race with any writes.
      return true;
    }
  }
  return false;
}

void Memcov::chooseInstructionsToInstrument(
    SmallVectorImpl<Instruction *> &Local, SmallVectorImpl<Instruction *> &All,
    const DataLayout &DL) {
  SmallPtrSet<Value *, 8> WriteTargets;
  // Iterate from the end.
  for (Instruction *I : reverse(Local)) {
    if (StoreInst *Store = dyn_cast<StoreInst>(I)) {
      Value *Addr = Store->getPointerOperand();
      if (!shouldInstrumentReadWriteFromAddress(I->getModule(), Addr))
        continue;
      WriteTargets.insert(Addr);
    } else {
      LoadInst *Load = cast<LoadInst>(I);
      Value *Addr = Load->getPointerOperand();
      if (!shouldInstrumentReadWriteFromAddress(I->getModule(), Addr))
        continue;
      if (addrPointsToConstantData(Addr))
        // Addr points to some constant data -- it can not race with any
        // writes.
        continue;
    }
    Value *Addr = isa<StoreInst>(*I) ? cast<StoreInst>(I)->getPointerOperand()
                                     : cast<LoadInst>(I)->getPointerOperand();
    if (isa<AllocaInst>(getUnderlyingObject(Addr)) &&
        !PointerMayBeCaptured(Addr, true, true)) {
      // The variable is addressable but not captured, so it cannot be
      // referenced from a different thread and participate in a data race
      // (see llvm/Analysis/CaptureTracking.h for details).
      continue;
    }
    All.push_back(I);
  }
  Local.clear();
}

bool Memcov::isInterestingLoadStore(Instruction *I) {
  if (auto *LI = dyn_cast<LoadInst>(I))
    return !LI->isAtomic() && LI->getSyncScopeID() != SyncScope::SingleThread;
  else if (auto *SI = dyn_cast<StoreInst>(I))
    return !SI->isAtomic() && SI->getSyncScopeID() != SyncScope::SingleThread;
  else
    return false;
}

static bool isBUG_X86_64(Instruction *I) {
  if (CallInst *CI = dyn_cast<CallInst>(I)) {
    if (CI->isInlineAsm()) {
      auto *Asm = cast<InlineAsm>(CI->getCalledOperand());
      auto Str = Asm->getAsmString();
#define UD2 ".byte 0x0f, 0x0"
      return Str.find(UD2) != std::string::npos;
    }
  }
  return false;
}

bool Memcov::isBUG(Instruction *I) {
  if (TargetArchitecture == X86_64) {
    return isBUG_X86_64(I);
  } else {
    // TODO: aarch64
    return false;
  }
}

bool Memcov::instrumentAll(Function &F, const TargetLibraryInfo &TLI) {
  LLVM_DEBUG(dbgs() << "=== Instrumenting a function " << F.getName()
                    << " ===\n");

  // Early checks
  if (F.hasFnAttribute(Attribute::NoSoftStoreBuffer))
    return false;

  if (F.getSection() == ".noinstr.text")
    return false;

  // Now we are instrumenting callbacks
  bool Res = false;
  bool HasCalls = false;
  const DataLayout &DL = F.getParent()->getDataLayout();

  // Visiting and cheking all instructions
  for (auto &BB : F) {
    for (auto &Inst : BB) {
      if (isInterestingLoadStore(&Inst))
        LocalLoadsAndStores.push_back(&Inst);
      else if (isa<CallInst>(Inst) || isa<InvokeInst>(Inst)) {
        if (CallInst *CI = dyn_cast<CallInst>(&Inst))
          maybeMarkSanitizerLibraryCallNoBuiltin(CI, &TLI);
        HasCalls = true;
        chooseInstructionsToInstrument(LocalLoadsAndStores, AllLoadsAndStores,
                                       DL);
        if (isBUG(&Inst))
          break;
      }
    }
    chooseInstructionsToInstrument(LocalLoadsAndStores, AllLoadsAndStores, DL);
  }

  // We have collected all loads and stores.
  for (auto Inst : AllLoadsAndStores)
    Res |= instrumentLoadOrStore(Inst, DL);

  return Res | HasCalls;
}

bool Memcov::instrumentFunction(Function &F, const TargetLibraryInfo &TLI) {
  initialize(*F.getParent());
  return instrumentAll(F, TLI);
}

bool Memcov::instrumentLoadOrStore(Instruction *I, const DataLayout &DL) {
  auto NI = I->getNextNonDebugInstruction();
  auto Loc = I->getDebugLoc();
  IRBuilder<> IRB(NI);
  bool IsWrite = isa<StoreInst>(*I);
  Value *Addr = IsWrite ? cast<StoreInst>(I)->getPointerOperand()
                        : cast<LoadInst>(I)->getPointerOperand();
  FunctionCallee OnAccessFunc = nullptr;

  // swifterror memory addresses are mem2reg promoted by instruction
  // selection. As such they cannot have regular uses like an instrumentation
  // function and it makes no sense to track them as memory.
  if (Addr->isSwiftError())
    return false;

  int Idx = getMemoryAccessFuncIndex(Addr, DL);
  if (Idx < 0)
    return false;
  OnAccessFunc = IsWrite ? MemcovStore[Idx] : MemcovLoad[Idx];

  LLVM_DEBUG(dbgs() << "Instrumenting a " << (IsWrite ? "store" : "load")
                    << " callback at " << *I << "\n");

  if (IsWrite)
    NumInstrumentedWrites++;
  else
    NumInstrumentedReads++;

  auto Args = SmallVector<Value *, 8>();
  Args.push_back(IRB.CreatePointerCast(Addr, IRB.getInt8PtrTy()));
  if (IsWrite) {
    // Store requires one more argument
    Args.push_back(
        IRB.CreatePointerCast(I->getOperand(0) /* == SI->getValueOperand() */,
                              IRB.getIntNTy((1U << Idx) * 8)));
  }
  auto CI = IRB.CreateCall(OnAccessFunc, Args);
  CI->setDebugLoc(Loc);
  return true;
}

static void dumpIR(Function &F, std::string prefix) {
  const char *tmpdirp;
  std::string tmpdir;
  if ((tmpdirp = std::getenv("TMP_DIR")))
    tmpdir.append(tmpdirp);

  std::string fn = tmpdir + "/" + F.getName().str() + "." + prefix + ".ll";
  std::error_code EC;

  raw_fd_ostream out(fn, EC, sys::fs::OF_Text);

  F.print(out, NULL /*default*/, false /*default*/, true /*IsForDebug*/);
}

static bool visitor(Function &F, const TargetLibraryInfo &TLI) {
  Memcov Memcov;
  bool ret;
  if (ClDumpIRs)
    dumpIR(F, std::string("before"));
  ret = Memcov.instrumentFunction(F, TLI);
  if (ClDumpIRs)
    dumpIR(F, std::string("after"));
  return ret;
}

void Memcov::initialize(Module &M) {
  TargetMemoryModel = PSO;
  TargetArchitecture = X86_64;
  IRBuilder<> IRB(M.getContext());
  AttributeList Attr;
  Attr = Attr.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                           Attribute::NoUnwind);
  std::string TargetMemoryModelStr = (TargetMemoryModel == TSO) ? "tso" : "pso";
  for (size_t i = 0; i < kNumberOfAccessSizes; i++) {
    const unsigned ByteSize = 1U << i;
    const unsigned BitSize = ByteSize * 8;
    std::string ByteSizeStr = utostr(ByteSize);
    std::string BitSizeStr = utostr(BitSize);
    Type *IntNTy = IRB.getIntNTy(BitSize);
    SmallString<32> StoreName("__ssb_" + TargetMemoryModelStr + "_store" +
                              ByteSizeStr);
    MemcovStore[i] = M.getOrInsertFunction(StoreName, Attr, IRB.getVoidTy(),
                                           IRB.getInt8PtrTy(), IntNTy);
    SmallString<32> LoadName("__ssb_" + TargetMemoryModelStr + "_load" +
                             ByteSizeStr);
    MemcovLoad[i] =
        M.getOrInsertFunction(LoadName, Attr, IntNTy, IRB.getInt8PtrTy());
  }
}

int Memcov::getMemoryAccessFuncIndex(Value *Addr, const DataLayout &DL) {
  Type *OrigPtrTy = Addr->getType();
  Type *OrigTy = cast<PointerType>(OrigPtrTy)->getElementType();
  assert(OrigTy->isSized());
  uint32_t TypeSize = DL.getTypeStoreSizeInBits(OrigTy);
  if (TypeSize != 8 && TypeSize != 16 && TypeSize != 32 && TypeSize != 64) {
    NumAccessesWithBadSize++;
    // Ignore all unusual sizes.
    return -1;
  }
  size_t Idx = countTrailingZeros(TypeSize / 8);
  assert(Idx < kNumberOfAccessSizes);
  return Idx;
}

/*
 * Legacy PassManager stuffs
 */
struct MemcovLegacy : public FunctionPass {
  static char ID;
  StringRef getPassName() const override;
  void getAnalysisUsage(AnalysisUsage &AU) const override;
  MemcovLegacy() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override {
    auto &TLI = getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
    return visitor(F, TLI);
  }
};

char MemcovLegacy::ID = 0;

StringRef MemcovLegacy::getPassName() const { return "MemcovLegacyPass"; }

void MemcovLegacy::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<TargetLibraryInfoWrapperPass>();
}

static RegisterPass<MemcovLegacy>
    X("ssb", "Memcov Pass",
      true, // This pass doesn't modify the CFG => true
      false // This pass is not a pure analysis pass => false
    );

static llvm::RegisterStandardPasses
    Y(llvm::PassManagerBuilder::EP_OptimizerLast,
      [](const llvm::PassManagerBuilder &Builder,
         llvm::legacy::PassManagerBase &PM) { PM.add(new MemcovLegacy()); });

} // namespace

/*
 * New PassManager stuffs
 */
PreservedAnalyses MemcovPass::run(Function &F, FunctionAnalysisManager &FAM) {
  // TODO: We are not using the new pass manager stuff. Implement this
  // later.
  // visitor(F, FAM.getResult<TargetLibraryAnalysis>(F));
  return PreservedAnalyses::all();
}

llvm::PassPluginLibraryInfo getMemcovPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "Memcov", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "ssb") {
                    FPM.addPass(MemcovPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getMemcovPluginInfo();
}
