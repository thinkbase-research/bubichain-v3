#bubi daemon module CmakeLists.txt

set(DEAMON_DEPENDS_LIB ssl crypto)

# -- bubi_bubid -- #
set(BIN_BUBI_ID bubid)

add_executable(${BIN_BUBI_ID} bubi/main.cpp)
target_link_libraries(${BIN_BUBI_ID} -Wl,-dn ${DEAMON_DEPENDS_LIB} ${BUBI_LINKER_FLAGS})

target_compile_options(${BIN_BUBI_ID}
    PUBLIC -std=c++11 
)

install(TARGETS ${BIN_BUBI_ID}
    RUNTIME DESTINATION ${BUBICHAIN}/bin
)

## -- bubi_monitord -- #
#set(BIN_MONITORD monitord)
#add_executable(${BIN_MONITORD} monitor/monitor/main.cpp)
#target_link_libraries(${BIN_MONITORD} ${DEAMON_DEPENDS_LIB})
#
## -- monitor_detection -- #
#set(BIN_DETECTION monitor_detection)
#add_executable(${BIN_DETECTION} monitor/detection/monitor_detection.cpp)
#target_link_libraries(${BIN_DETECTION} zmq)

# -- bubi_slaved -- #
#set(BIN_SLAVED bubi_slaved)
#add_executable(${BIN_SLAVED} slave/main.cpp)
#target_link_libraries(${BIN_SLAVED} ${DEAMON_DEPENDS_LIB})
