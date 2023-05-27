#ifndef __MEMCOV_H
#define __MEMCOV_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class MemcovPass : public PassInfoMixin<MemcovPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

} // namespace llvm

#endif // __MEMCOV_H
