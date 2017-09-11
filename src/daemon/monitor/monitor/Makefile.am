bin_PROGRAMS = bubi_monitord
bubi_monitord_SOURCES = main.cpp
bubi_monitord_CXXFLAGS = -std=c++11 \
					  $(NULL)
bubi_monitord_LDADD =	\
				$(top_builddir)/src/3rd/openssl/libssl.a \
				$(top_builddir)/src/3rd/openssl/libcrypto.a \
				-lpthread -ldl \
				$(NULL)
					
bubi_monitord_LDFLAGS = -static-libstdc++ -static-libgcc