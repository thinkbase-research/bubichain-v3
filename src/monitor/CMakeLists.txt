#bubi monitor module CmakeLists.txt -- bubi_monitor
set(BIN_BUBI_MONITOR bubi_monitor)

set(MONITOR_SRC 
    main.cpp monitor.cpp alert.cpp notice.cpp
    monitor_network.cpp monitor_manager.cpp configure.cpp
)

set(MONITOR_DEPENDS_LIB
    libbubi_common.a libbubi_utils.a libbubi_proto.a libcurl.a ${BUBI_DEPENDS_LIBS}
)

#generate executable file
add_executable(${BIN_BUBI_MONITOR} ${MONITOR_SRC})

#specify dependent libraries for target obj
target_link_libraries(${BIN_BUBI_MONITOR} ${MONITOR_DEPENDS_LIB} ${BUBI_LINKER_FLAGS})

#specify compile options for target obj
target_compile_options(${BIN_BUBI_MONITOR}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
    PUBLIC -D_WEBSOCKETPP_CPP11_STL_
)
