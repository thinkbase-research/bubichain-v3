JSONCPP = $(top_builddir)/src/3rd/jsoncpp/libs/libjson.a
LIBSSL = $(top_builddir)/src/3rd/openssl/libssl.a
LIBCRYPTO = $(top_builddir)/src/3rd/openssl/libcrypto.a
LIBZ = $(top_builddir)/src/3rd/zlib-1.2.8/libz.a
LIBBZ2 = $(top_builddir)/src/3rd/bzip2-1.0.6/libbz2.a

bin_PROGRAMS = bubi_ca

bubi_ca_SOURCES = main.cpp configure.cpp \
				manager.cpp

bubi_ca_CXXFLAGS = -std=c++11 -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_ \
					-I$(top_srcdir)/src \
					-I$(top_srcdir)/src/3rd/jsoncpp/include/ \
					-I$(top_srcdir)/src/3rd/asio/include \
					-I$(top_srcdir)/src/3rd/openssl/include \
					-I$(top_srcdir)/src/3rd/http \
					 $(NULL)
					 
bubi_ca_LDFLAGS = -static -static-libstdc++ -static-libgcc 

bubi_ca_LDADD =	\
				$(top_builddir)/src/common/libbubi_common.a \
				$(top_builddir)/src/utils/libbubi_utils.a \
				$(JSONCPP) \
				$(LIBSSL) \
				$(LIBCRYPTO) \
				$(LIBZ) \
				$(LIBBZ2) \
				-lpthread -lrt -ldl \
				$(NULL)
					