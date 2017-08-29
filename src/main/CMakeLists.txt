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
)

set(INNER_LIBS bubi_glue bubi_ledger bubi_consensus bubi_overlay bubi_common bubi_utils bubi_proto bubi_http bubi_ed25519 bubi_monitor)
set(V8_LIBS v8_base v8_libbase v8_external_snapshot v8_libplatform v8_libsampler icui18n icuuc inspector)

#generate executable file
add_executable(${APP_BUBI} ${APP_BUBI_SRC})

#specify dependent libraries for target obj
target_link_libraries(${APP_BUBI}
    -Wl,-dn ${INNER_LIBS} -Wl,--start-group ${V8_LIBS} -Wl,--end-group ${BUBI_DEPENDS_LIBS} ${BUBI_LINKER_FLAGS})

#specify compile options for target obj
target_compile_options(${APP_BUBI}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
    PUBLIC -D_WEBSOCKETPP_CPP11_STL_
)

install(TARGETS ${APP_BUBI}
    RUNTIME DESTINATION ${BUBICHAIN}/bin
)
