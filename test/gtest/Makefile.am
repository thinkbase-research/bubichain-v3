JSONCPP = $(top_builddir)/src/3rd/jsoncpp/libs/libjson.a
LIBSSL = $(top_builddir)/src/3rd/openssl/libssl.a
LIBCRYPTO = $(top_builddir)/src/3rd/openssl/libcrypto.a
LIBZ = $(top_builddir)/src/3rd/zlib-1.2.8/libz.a
LIBBZ2 = $(top_builddir)/src/3rd/bzip2-1.0.6/libbz2.a
GTEST = $(top_builddir)/src/3rd/gtest/gtest.a

UTILS_SOURCE = $(top_builddir)/src/utils/file.cpp \
		$(top_builddir)/src/utils/logger.cpp \
                $(top_builddir)/src/utils/net.cpp \
                $(top_builddir)/src/utils/thread.cpp \
                $(top_builddir)/src/utils/timestamp.cpp \
                $(top_builddir)/src/utils/utils.cpp  \
                $(top_builddir)/src/utils/crypto.cpp \
                $(top_builddir)/src/utils/lrucache.hpp \
                $(top_builddir)/src/utils/noncopyable.h \
                $(top_builddir)/src/utils/timer.cpp \
                $(top_builddir)/src/utils/timestamp.cpp \
                $(top_builddir)/src/utils/system.cpp\
                $(top_builddir)/src/utils/$(NULL)

COMMON_SOURCE = $(UTILS_SOURCE)\
		$(top_srcdir)/src/common/ecc_sm2.cpp \
		$(top_srcdir)/src/common/private_key.cpp



bin_PROGRAMS = cpptest


  

cpptest_SOURCES = ../../src/utils/file.cpp\
		../../src/utils/logger.cpp\
		../../src/utils/net.cpp\
		../../src/utils/thread.cpp\
		../../src/utils/timestamp.cpp\
		../../src/utils/utils.cpp\
		../../src/utils/crypto.cpp\
		../../src/utils/lrucache.hpp\
		../../src/utils/noncopyable.h\
		../../src/utils/timer.cpp\
		../../src/utils/system.cpp\
	common/web_socket_server.cpp\
		common/websocket_test.cpp\
		common/websocket_test_nobubi.cpp\
		common/http_client.cpp\
		main.cpp

cpptest_LDFLAGS = -static -static-libstdc++ -static-libgcc

cpptest_CXXFLAGS =                             -std=c++11 -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_ \
                                                        -I$(top_srcdir)/src/3rd/jsoncpp/include \
                                                        -I$(top_srcdir)/src/  \
                                                        -I$(top_srcdir)/src/3rd/basic/include/mysql \
                                                        -I$(top_srcdir)/src/3rd/protobuf/src/ \
                                                        -I$(top_srcdir)/src/3rd/asio/include \
                                                        -I$(top_srcdir)/src/3rd/sqlite \
                                                        -I$(top_srcdir)/src/3rd/rocksdb/include \
                                                        -I$(top_srcdir)/src/3rd/soci/include \
                                                        -I$(top_srcdir)/src/3rd/postgresql-9.4.0/src/interfaces/libpq \
                                                        -I$(top_srcdir)/src/3rd/postgresql-9.4.0/src/include/ \
							-I$(top_srcdir)/src/3rd/zeromq/zeromq-4.1.5/include \
                                                        -I$(top_srcdir)/src/3rd/openssl/include \
                                                        -I$(top_srcdir)/src/3rd/bzip2-1.0.6 \
                                                        -I$(top_srcdir)/src/3rd/zlib-1.2.8 \
							-I$(top_srcdir)/src/3rd/gtest/include \
							-I$(top_srcdir)/src/3rd/websocketpp \
                                                        $(NULL)

cpptest_LDADD = \
				$(LIBZMQ) \
                                $(CURL) \
                                $(LIBSSL) \
                                $(LIBCRYPTO) \
                                $(JSONCPP) \
                                $(LIBZ) \
                                $(LIBBZ2) \
				$(GTEST)\
                                -lpthread -lrt -ldl \
                                $(NULL)
