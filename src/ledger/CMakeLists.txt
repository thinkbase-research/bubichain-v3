#bubi ledger module CmakeLists.txt -- libbubi_ledger.a

set(LIB_BUBI_LEDGER bubi_ledger)

#automaticall get src file in specifical dir
aux_source_directory(${BUBI_SRC_DIR}/ledger/ LEDGER_SRC)

#generate static library file
add_library(${LIB_BUBI_LEDGER} ${LEDGER_SRC})

#specify compile options for target obj
target_compile_options(${LIB_BUBI_LEDGER}
    PUBLIC -std=c++11 
    PUBLIC -DASIO_STANDALONE
    PUBLIC -D_WEBSOCKETPP_CPP11_STL_
)
