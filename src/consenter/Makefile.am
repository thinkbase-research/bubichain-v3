LIBZMQ = $(top_builddir)/src/3rd/zeromq/zeromq-4.2.1/src/.libs/libzmq.a
PROTOBUF = $(top_builddir)/src/3rd/protobuf/src/.libs/libprotobuf.a
ROCKSDB = $(top_builddir)/src/3rd/rocksdb/librocksdb.a
JSONCPP = $(top_builddir)/src/3rd/jsoncpp/libs/libjson.a
LIBSSL = $(top_builddir)/src/3rd/openssl/libssl.a
LIBCRYPTO = $(top_builddir)/src/3rd/openssl/libcrypto.a
LIBZ = $(top_builddir)/src/3rd/zlib-1.2.8/libz.a
LIBBZ2 = $(top_builddir)/src/3rd/bzip2-1.0.6/libbz2.a
POSTGRE = $(top_builddir)/src/3rd/postgresql-9.4.0/src/interfaces/libpq/libpq.a 
MYSQL = $(top_builddir)/src/3rd/basic/lib/libmysqlclient_x64.a
LIBAPI = $(top_builddir)/src/api/libbubi_api.a
LIBBSON = $(top_builddir)/src/3rd/mongo-c-driver/src/libbson/.libs/libbson-1.0.a
MONGOC = $(top_builddir)/src/3rd/mongo-c-driver/.libs/libmongoc-1.0.a
PCREPOSIX = $(top_builddir)/src/3rd/pcre-8.39/.libs/libpcreposix.a
PCRECPP = $(top_builddir)/src/3rd/pcre-8.39/.libs/libpcrecpp.a	
PCRE = $(top_builddir)/src/3rd/pcre-8.39/.libs/libpcre.a

if bit_32
	MYSQL = $(top_builddir)/src/3rd/basic/lib/libmysqlclient_x86.a
endif

bin_PROGRAMS = bubi

bubi_SOURCES = main.cpp \
				../api/web_server.cpp \
				../api/web_server_query.cpp \
				../api/web_server_update.cpp \
				../api/web_server_command.cpp \
				../api/web_server_helper.cpp \
				../api/mq_server.cpp \
				../slave/master_service.cpp \
				../slave/slave_executor.cpp \
				../monitor/monitor_master.cpp \
				../monitor/monitoragent.cpp \
				../monitor/system_manager.cpp

bubi_CXXFLAGS = -std=c++11 -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_ -DBUBI_TLS \
					-I$(top_srcdir)/src \
					-I$(top_srcdir)/src/3rd/basic/include/mysql \
					-I$(top_srcdir)/src/3rd/protobuf/src/ \
					-I$(top_srcdir)/src/3rd/jsoncpp/include/ \
					-I$(top_srcdir)/src/3rd/asio/include \
					-I$(top_srcdir)/src/3rd/sqlite \
					-I$(top_srcdir)/src/3rd/rocksdb/include \
					-I$(top_srcdir)/src/3rd/mongo-c-driver/src/mongoc \
					-I$(top_srcdir)/src/3rd/mongo-c-driver/src/libbson/src/bson \
					-I$(top_srcdir)/src/3rd/pcre-8.39 \
					-I$(top_srcdir)/src/3rd/soci/include \
					-I$(top_srcdir)/src/3rd/postgresql-9.4.0/src/interfaces/libpq \
			        -I$(top_srcdir)/src/3rd/postgresql-9.4.0/src/include/ \
					-I$(top_srcdir)/src/3rd/websocketpp \
					-I$(top_srcdir)/src/3rd/openssl/include \
					-I$(top_srcdir)/src/3rd/bzip2-1.0.6 \
					-I$(top_srcdir)/src/3rd/zlib-1.2.8 \
					-I$(top_srcdir)/src/3rd/zeromq/zeromq-4.2.1/include \
					-I$(top_srcdir)/src/api/ \
					 $(NULL)
					 
bubi_LDFLAGS = -static -static-libstdc++ -static-libgcc 

bubi_LDADD =	\
				$(top_builddir)/src/glue/libbubi_glue.a \
				$(top_builddir)/src/ledger/libbubi_ledger.a \
				$(top_builddir)/src/consensus/libbubi_consensus.a \
				$(top_builddir)/src/overlay/libbubi_overlay.a \
				$(top_builddir)/src/common/libbubi_common.a \
				$(top_builddir)/src/utils/libbubi_utils.a \
				$(top_builddir)/src/proto/libbubi_proto.a \
				$(top_builddir)/src/3rd/http/libbubi_http.a \
				$(top_builddir)/src/3rd/ed25519-donna/libbubi_ed25519.a \
				$(LIBZMQ) \
				$(PROTOBUF) \
				$(ROCKSDB) \
				$(MONGOC) \
				$(LIBBSON) \
				$(PCRECPP) \
				$(PCREPOSIX) \
				$(PCRE) \
				$(JSONCPP) \
				$(LIBSSL) \
				$(LIBCRYPTO) \
				$(LIBZ) \
				$(LIBBZ2) \
				-lpthread -lrt -ldl \
				$(POSTGRE) \
				$(MYSQL) \
				$(NULL)
					