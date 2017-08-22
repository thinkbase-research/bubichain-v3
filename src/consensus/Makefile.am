PROTOBUF = $(top_builddir)/src/protobuf/src/.libs/libprotobuf.so
PROTOBUF_PATH = $(top_builddir)/src/protobuf

$(PROTOBUF) :
	@echo "*************building protobuf now***************" && cd $(PROTOBUF_PATH) && ./autogen.sh && ./configure --prefix=/usr && $(MAKE) && $(MAKE) install

noinst_LIBRARIES = libbubi_consensus.a

libbubi_consensus_a_SOURCES =	\
						  consensus_manager.cpp \
						  consensus_msg.cpp \
						  consensus.cpp \
						  pbft.cpp \
						  pbft_instance.cpp \
							$(NULL)

libbubi_consensus_a_CXXFLAGS = -std=c++11 -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_ \
							-I$(top_srcdir)/src \
							-I$(top_srcdir)/src/3rd/basic/include/mysql \
							-I$(top_builddir)/src/3rd/protobuf/src/	\
							-I$(top_builddir)/src/3rd/jsoncpp/include \
							-I$(top_srcdir)/src/3rd/asio/include \
							-I$(top_srcdir)/src/3rd/sqlite \
							-I$(top_srcdir)/src/3rd/rocksdb/include \
							-I$(top_srcdir)/src/3rd/websocketpp \
							-I$(top_srcdir)/src/3rd/openssl/include \
							-I$(top_srcdir)/src/3rd/bzip2 \
							-I$(top_srcdir)/src/3rd/zlib \
							 $(NULL)

