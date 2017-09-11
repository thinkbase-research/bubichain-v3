#bubi monitor module CmakeLists.txt -- libbubi_monitor.a
set(LIB_BUBI_MONITOR bubi_monitor)

#automaticall get src file in specifical dir
aux_source_directory(${BUBI_SRC_DIR}/monitor/ MONITOR_SRC)

#generate static library file
add_library(${LIB_BUBI_MONITOR} ${MONITOR_SRC})

#specify compile options for target obj
target_compile_options(${LIB_BUBI_MONITOR}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
    PUBLIC -D_WEBSOCKETPP_CPP11_STL_
)