set(MemcovPass_src
  MemcovPass.cpp
  )

add_library(MemcovPass SHARED ${MemcovPass_src})

# Run clang-format before build
add_custom_command(TARGET MemcovPass
  PRE_BUILD
  DEPENDS ${MemcovPass_src}
  COMMAND clang-format -i -style=file ${MemcovPass_src}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )

target_include_directories(MemcovPass
  PRIVATE "${PROJECT_SOURCE_DIR}/include"
  )

install(TARGETS MemcovPass DESTINATION lib)
