cmake_minimum_required(VERSION 3.20)

set(TARGET go_spao)
set(SRCS spao.go)
set(LIB spao.so)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${LIB}
  DEPENDS ${SRCS}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND env GOPATH=${GOPATH} go build -buildmode=c-archive
  -o "${CMAKE_CURRENT_BINARY_DIR}/${LIB}"
  ${CMAKE_GO_FLAGS} ./...
  COMMENT "Generating ${LIB}")

add_custom_target(${TARGET} DEPENDS ${LIB} ${HEADER})
add_library(spao STATIC IMPORTED GLOBAL)
add_dependencies(spao ${TARGET})
set_target_properties(spao
  PROPERTIES
  IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${LIB}
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR})