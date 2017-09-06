cmake_minimum_required(VERSION 2.8)

project(bubi)
add_compile_options(-g -O2)
add_definitions(-DSVNVERSION=\"${SVNVERSION}\")
message(STATUS "-DSVNVERSION="${SVNVERSION})

set(BUBICHAIN bubichain)
set(BUBI_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(BUBI_ROOT_DIR ${BUBI_SRC_DIR}/..)
set(LIBRARY_OUTPUT_PATH ${BUBI_ROOT_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${BUBI_ROOT_DIR}/bin)
set(BUBI_LINKER_FLAGS "-Wl,-dy -lpthread -lrt -ldl")

execute_process(COMMAND make all -j8 WORKING_DIRECTORY ${BUBI_SRC_DIR}/3rd)

include_directories(
    ${BUBI_SRC_DIR}
    ${BUBI_SRC_DIR}/3rd/basic/include/v8
    ${BUBI_SRC_DIR}/3rd/protobuf/src
    ${BUBI_SRC_DIR}/3rd/jsoncpp/include
    ${BUBI_SRC_DIR}/3rd/sqlite 
    ${BUBI_SRC_DIR}/3rd/rocksdb/include
    ${BUBI_SRC_DIR}/3rd/pcre-8.39
    ${BUBI_SRC_DIR}/3rd/websocketpp
    ${BUBI_SRC_DIR}/3rd/bzip2-1.0.6
    ${BUBI_SRC_DIR}/3rd/zlib-1.2.8
    ${BUBI_SRC_DIR}/3rd/asio/include
    ${BUBI_SRC_DIR}/3rd/openssl/include
    ${BUBI_SRC_DIR}/3rd/http
)

link_directories(
    ${BUBI_SRC_DIR}/3rd/protobuf/src/.libs
    ${BUBI_SRC_DIR}/3rd/rocksdb
    ${BUBI_SRC_DIR}/3rd/pcre-8.39/.libs
    ${BUBI_SRC_DIR}/3rd/jsoncpp/libs
    ${BUBI_SRC_DIR}/3rd/openssl
    ${BUBI_SRC_DIR}/3rd/zlib-1.2.8
    ${BUBI_SRC_DIR}/3rd/bzip2-1.0.6
    ${BUBI_SRC_DIR}/3rd/basic/lib
    ${BUBI_SRC_DIR}/3rd/curl/lib/.libs/
    ${LIBRARY_OUTPUT_PATH}
)

set(BUBI_DEPENDS_LIBS protobuf rocksdb pcreposix pcrecpp pcre json ssl crypto z bz2)

add_subdirectory(3rd/http)
add_subdirectory(3rd/ed25519-donna)
add_subdirectory(glue)
add_subdirectory(utils)
add_subdirectory(proto)
add_subdirectory(ledger)
add_subdirectory(common)
add_subdirectory(overlay)
add_subdirectory(consensus)
add_subdirectory(ca)
add_subdirectory(daemon)
add_subdirectory(monitor)
add_subdirectory(main)

set(BUBI_SCRIPTS ${BUBI_ROOT_DIR}/deploy)
install(
    PROGRAMS ${BUBI_SCRIPTS}/bubi ${BUBI_SCRIPTS}/bubid ${BUBI_SCRIPTS}/start-stop-daemon
    DESTINATION ${BUBICHAIN}/scripts
)

install(
    DIRECTORY ${BUBI_SRC_DIR}/3rd/basic/bin/
    DESTINATION ${BUBICHAIN}/bin
    FILES_MATCHING PATTERN "*.bin" PATTERN "*.dat"
)

install(
    DIRECTORY ${BUBI_ROOT_DIR}/build/win32/config/
    DESTINATION ${BUBICHAIN}/config
    REGEX "slave.json|test_case.json|monitor.json|ca.pem" EXCLUDE
)

set(SUPPLEMENT ${BUBI_ROOT_DIR}/build/linux/MakeSupplement)
set(FIX_DIR ${CMAKE_INSTALL_PREFIX}/${BUBICHAIN})
message(STATUS "install dir: ${FIX_DIR}")

file(WRITE ${SUPPLEMENT} "soft_link:\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s ${FIX_DIR}/scripts/bubi /etc/init.d/bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s ${FIX_DIR}/scripts/bubid /etc/init.d/bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubi /etc/rc1.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubi /etc/rc1.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubi /etc/rc2.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubi /etc/rc3.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubi /etc/rc4.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubi /etc/rc5.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubid /etc/rc1.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubid /etc/rc1.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubid /etc/rc2.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubid /etc/rc3.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubid /etc/rc4.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo ln -s -f /etc/init.d/bubid /etc/rc5.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\tsudo mkdir -p ${FIX_DIR}/data;\n")

file(APPEND ${SUPPLEMENT} "\nuninstall:\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc1.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc2.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc3.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc4.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc5.d/S99bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/init.d/bubi;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc1.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc2.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc3.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc4.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/rc5.d/S50bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -f /etc/init.d/bubid;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -rf ${FIX_DIR}/bin;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -rf ${FIX_DIR}/cfca;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -rf ${FIX_DIR}/config;\\\n")
file(APPEND ${SUPPLEMENT} "\trm -rf ${FIX_DIR}/scripts\n")
