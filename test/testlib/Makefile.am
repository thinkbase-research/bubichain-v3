PROTOBUF := $(top_builddir)/src/3rd/protobuf/src/.libs/libprotobuf.a
PROTOBUF_PATH := $(top_builddir)/src/3rd/protobuf

ROCKSDB := $(top_builddir)/src/3rd/rocksdb/librocksdb.a
ROCKSDB_PATH := $(top_builddir)/src/3rd/rocksdb

SQLITE3 := $(top_builddir)/src/3rd/sqlite/sqlite3.o
SQLITE3_PATH := $(top_builddir)/src/3rd/sqlite

noinst_PROGRAMS = bubi_test

bubi_test_SOURCES = test.cpp test_json.cpp test_sqlite.cpp
bubi_test_CXXFLAGS = -std=c++11 -DASIO_STANDALONE	\
					-I$(top_builddir)/src/3rd/rocksdb/include	\
					-I$(top_builddir)/src/3rd/sqlite \
					-I$(top_srcdir)/src/3rd/asio/include \
					$(NULL)

bubi_test_LDADD =  \
					$(top_builddir)/src/keygen/libbubi_keygen.a \
					$(top_builddir)/src/utils/libbubi_utils.a \
					-lcrypto -lssl -lpthread -lz -lrt -ldl \
					$(SQLITE3) \
					$(top_builddir)/src/3rd/jsoncpp/libs/linux-gcc-4.9.2/libjson_linux-gcc-4.9.2_libmt.a \
					$(NULL)
INCLUDES=-I$(top_srcdir)/src \
	 -I$(top_builddir)/src/3rd/jsoncpp/include/
