#bubi ca module CmakeLists.txt -- bubi_ca

set(BIN_BUBI_CA bubi_ca)
set(CA_DEPENDS_LIBS bubi_common bubi_utils ${BUBI_DEPENDS_LIBS})

#automaticall get src file in specifical dir
aux_source_directory(${BUBI_SRC_DIR}/ca/ CA_SRC)

#generate executable file
add_executable(${BIN_BUBI_CA} ${CA_SRC})

#specify dependent libraries for target obj
target_link_libraries(${BIN_BUBI_CA} ${CA_DEPENDS_LIBS} ${BUBI_LINKER_FLAGS})

#specify compile options for target obj
target_compile_options(${BIN_BUBI_CA}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
    PUBLIC -D_WEBSOCKETPP_CPP11_STL_
)

install(TARGETS ${BIN_BUBI_CA}
    RUNTIME DESTINATION ${BUBICHAIN}/bin
)

