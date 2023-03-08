file(GLOB_RECURSE HDR_FILES *.hpp)
file(GLOB_RECURSE SRC_FILES *.cpp)

add_library(tsntranslator ${HDR_FILES} ${SRC_FILES})

target_compile_options(tsntranslator PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)

target_link_libraries(tsntranslator common-lib)
target_link_libraries(tsntranslator asn-ngap)