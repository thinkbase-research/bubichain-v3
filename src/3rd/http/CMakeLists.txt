#bubi http module CmakeLists.txt -- libbubi_http.a

set(LIB_BUBI_HTTP bubi_http)
aux_source_directory(${BUBI_SRC_DIR}/3rd/http/ HTTP_SRC)

add_library(${LIB_BUBI_HTTP} ${HTTP_SRC})

target_compile_options(${LIB_BUBI_HTTP}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
)
