#bubi glue module CmakeLists.txt -- libbubi_glue.a

set(LIB_BUBI_GLUE bubi_glue)

#automaticall get src file in specifical dir
aux_source_directory(${BUBI_SRC_DIR}/glue/ GLUE_SRC)

#generate static library file
add_library(${LIB_BUBI_GLUE} ${GLUE_SRC})

#specify compile options for target obj
target_compile_options(${LIB_BUBI_GLUE}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
    PUBLIC -D_WEBSOCKETPP_CPP11_STL_
)
