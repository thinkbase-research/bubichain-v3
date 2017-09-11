#bubi overlay module CmakeLists.txt -- libbubi_overlay.a

set(LIB_BUBI_OVERLAY bubi_overlay)
#automaticall get src file in specifical dir
aux_source_directory(${BUBI_SRC_DIR}/overlay/ OVERLAY_SRC)

#generate static library file
add_library(${LIB_BUBI_OVERLAY} ${OVERLAY_SRC})

#specify compile options for target obj
target_compile_options(${LIB_BUBI_OVERLAY}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
    PUBLIC -D_WEBSOCKETPP_CPP11_STL_
)
