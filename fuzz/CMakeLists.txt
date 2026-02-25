# Copyright 2015 The BoringSSL Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# TODO(crbug.com/42290412): Flatten this build up a layer. Between
# crbug.com/42290128, crbug.com/42290508 and crbug.com/42290554, there is enough
# churn that we've left it alone for now.
foreach(fuzzer ${FUZZ_SOURCES})
  cmake_path(GET fuzzer STEM name)
  add_executable(${name} ../${fuzzer})
  target_compile_options(${name} PRIVATE "-Wno-missing-prototypes")
  target_link_libraries(${name} ssl pki crypto)
  if(LIBFUZZER_FROM_DEPS)
    set_target_properties(${name} PROPERTIES LINK_FLAGS "-fsanitize=fuzzer-no-link")
    target_link_libraries(${name} Fuzzer)
  else()
    set_target_properties(${name} PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")
  endif()
  set_target_properties(
    ${name}
    PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES)
endforeach()
