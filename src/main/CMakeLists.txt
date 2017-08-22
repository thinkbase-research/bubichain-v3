#bubi main module CmakeLists.txt -- bubi

set(APP_BUBI bubi)

set(APP_BUBI_SRC
    main.cpp
    configure.cpp
    ../api/web_server.cpp
    ../api/web_server_query.cpp
    ../api/web_server_update.cpp
    ../api/web_server_command.cpp
    ../api/web_server_helper.cpp
    ../api/websocket_server.cpp
    ../monitor/monitor.cpp
    ../monitor/system_manager.cpp
)

set(INNER_LIBS
    libbubi_glue.a libbubi_ledger.a libbubi_consensus.a libbubi_overlay.a libbubi_common.a
    libbubi_utils.a libbubi_proto.a libbubi_http.a libbubi_ed25519.a
)

set(V8_LIBS
    libv8_base.a libv8_libbase.a libv8_external_snapshot.a libv8_libplatform.a
    libv8_libsampler.a libicui18n.a libicuuc.a libinspector.a
)

#generate executable file
add_executable(${APP_BUBI} ${APP_BUBI_SRC})

#specify dependent libraries for target obj
target_link_libraries(${APP_BUBI}
    ${INNER_LIBS}
    -Wl,--start-group
    ${V8_LIBS}
    -Wl,--end-group
    ${BUBI_DEPENDS_LIBS}
    ${BUBI_LINKER_FLAGS}
)

#specify compile options for target obj
target_compile_options(${APP_BUBI}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
    PUBLIC -D_WEBSOCKETPP_CPP11_STL_
)

install(TARGETS ${APP_BUBI}
    RUNTIME DESTINATION ${BUBICHAIN}/bin
)
