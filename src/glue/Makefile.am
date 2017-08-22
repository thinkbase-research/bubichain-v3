
noinst_LIBRARIES = libbubi_glue.a

libbubi_glue_a_SOURCES =	\
							glue_manager.cpp \
							transaction_set.cpp \
							ledger_upgrade.cpp \
							$(NULL)

libbubi_glue_a_CXXFLAGS = -std=c++11 -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_ \
							-I$(top_srcdir)/src \
							-I$(top_srcdir)/src/3rd/basic/include/mysql \
							-I$(top_builddir)/src/3rd/protobuf/src/	\
							-I$(top_builddir)/src/3rd/jsoncpp/include \
							-I$(top_srcdir)/src/3rd/asio/include \
							-I$(top_srcdir)/src/3rd/sqlite \
							-I$(top_srcdir)/src/3rd/rocksdb/include \
							-I$(top_srcdir)/src/3rd/websocketpp \
							-I$(top_srcdir)/src/3rd/openssl/include \
							 $(NULL)

