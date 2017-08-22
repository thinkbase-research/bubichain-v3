JSONCPP = $(top_builddir)/src/3rd/jsoncpp/libs/libjson.a
LIBSSL = $(top_builddir)/src/3rd/openssl/libssl.a
LIBCRYPTO = $(top_builddir)/src/3rd/openssl/libcrypto.a
CURL = $(top_builddir)/src/3rd/curl/lib/.libs/libcurl.a
LIBZ = $(top_builddir)/src/3rd/zlib-1.2.8/libz.a
LIBBZ2 = $(top_builddir)/src/3rd/bzip2-1.0.6/libbz2.a
PROTOBUF = $(top_builddir)/src/3rd/protobuf/src/.libs/libprotobuf.a

bin_PROGRAMS = bubi_monitor

bubi_monitor_SOURCES = \
				main.cpp \
				monitor.cpp \
				alert.cpp \
				notice.cpp \
				monitor_network.cpp \
				monitor_manager.cpp \
				configure.cpp
				
				

bubi_monitor_CXXFLAGS = -std=c++11 -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_ \
					-I$(top_srcdir)/src \
					-I$(top_srcdir)/src/3rd/protobuf/src/ \
					-I$(top_builddir)/src/3rd/jsoncpp/include/ \
					-I$(top_srcdir)/src/3rd/asio/include \
					-I$(top_srcdir)/src/3rd/openssl/include \
					-I$(top_srcdir)/src/3rd/websocketpp \
					-I$(top_srcdir)/src/3rd/bzip2-1.0.6 \
					-I$(top_srcdir)/src/3rd/zlib-1.2.8 \
					 $(NULL)

bubi_monitor_LDFLAGS =-static -static-libstdc++ -static-libgcc 

bubi_monitor_LDADD =	\
				$(top_builddir)/src/common/libbubi_common.a \
				$(top_builddir)/src/utils/libbubi_utils.a \
				$(top_builddir)/src/proto/libbubi_proto.a \
				$(PROTOBUF) \
				$(LIBSSL) \
				$(LIBCRYPTO) \
				$(JSONCPP) \
				$(LIBZ) \
				$(LIBBZ2) \
				-lpthread -lrt -ldl \
				$(NULL)