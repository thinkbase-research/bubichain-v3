PROTOBUF = $(top_builddir)/src/protobuf/src/.libs/libprotobuf.so
PROTOBUF_PATH = $(top_builddir)/src/protobuf

$(PROTOBUF) :
	@echo "*************building protobuf now***************" && cd $(PROTOBUF_PATH) && ./autogen.sh && ./configure --prefix=/usr && $(MAKE) && $(MAKE) install

noinst_LIBRARIES = libbubi_ledger.a

libbubi_ledger_a_SOURCES =	account.cpp		\
							ledger_frm.cpp \
							ledger_manager.cpp \
							operation_frm.cpp \
							transaction_frm.cpp \
							account.cpp \
							contract_manager.cpp \
							environment.cpp \
							kv_trie.cpp \
							trie.cpp \
							$(NULL)

libbubi_ledger_a_CXXFLAGS = -std=c++11 -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_ \
							-I$(top_srcdir)/src \
							-I$(top_srcdir)/src/3rd/basic/include/mysql \
							-I$(top_srcdir)/src/3rd/protobuf/src/	\
							-I$(top_srcdir)/src/3rd/jsoncpp/include \
							-I$(top_srcdir)/src/3rd/asio/include \
							-I$(top_srcdir)/src/3rd/sqlite \
							-I$(top_srcdir)/src/3rd/rocksdb/include \
							-I$(top_srcdir)/src/3rd/websocketpp \
							-I$(top_srcdir)/src/3rd/openssl/include \
							-I$(top_srcdir)/src/3rd/bzip2-1.0.6 \
							-I$(top_srcdir)/src/3rd/zlib-1.2.8 \
							-I$(top_srcdir)/src/3rd/v8_linux/centos/include \
							 $(NULL)

