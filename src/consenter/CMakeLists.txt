set(CONSENTER_BUBI consenter_bubi)
set(CONSENTER_BUBI_SRC
    main.cpp
    ../api/web_server.cpp
    ../api/web_server_query.cpp
    ../api/web_server_update.cpp
    ../api/web_server_command.cpp
    ../api/web_server_helper.cpp
    ../api/mq_server.cpp
    ../slave/master_service.cpp
    ../slave/slave_executor.cpp
    ../monitor/monitor_master.cpp
    ../monitor/monitoragent.cpp
    ../monitor/system_manager.cpp
)
set(CONSENTER_DEPENDS_LIBS
    bubi_glue bubi_ledger bubi_consensus bubi_overlay
    bubi_common bubi_utils bubi_proto bubi_http
    bubi_ed25519 zmq ${BUBI_DEPENDS_LIBS}
)

#generate executable file
add_executable(${CONSENTER_BUBI} ${CA_SRC})

#specify dependent libraries for target obj
target_link_libraries(${CONSENTER_BUBI} ${CONSENTER_DEPENDS_LIBS} ${BUBI_LINKER_FLAGS})

#specify compile options for target obj
target_compile_options(${CONSENTER_BUBI}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
    PUBLIC -D_WEBSOCKETPP_CPP11_STL_
    PUBLIC -DBUBI_TLS
)

