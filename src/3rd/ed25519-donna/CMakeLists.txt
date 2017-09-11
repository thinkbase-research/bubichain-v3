#bubi ed25519 module CmakeLists.txt -- libbubi_ed25519.a

set(LIB_BUBI_ED25519 bubi_ed25519)
aux_source_directory(${BUBI_SRC_DIR}/3rd/ed25519-donna/ ED25519_SRC)
add_library(${LIB_BUBI_ED25519} ${ED25519_SRC}) 

target_compile_options(${LIB_BUBI_ED25519} PUBLIC -DASIO_STANDALONE)
