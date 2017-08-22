noinst_LIBRARIES = libbubi_overlay.a

libbubi_overlay_a_SOURCES =	broadcast.cpp	\
							peer.cpp \
							peer_manager.cpp \
							peer_network.cpp \
							$(NULL)

libbubi_overlay_a_CXXFLAGS = -std=c++11 -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_ \
							-I$(top_srcdir)/src \
							-I$(top_srcdir)/src/3rd/basic/include/mysql \
							-I$(top_srcdir)/src/3rd/protobuf/src/	\
							-I$(top_srcdir)/src/3rd/jsoncpp/include \
							-I$(top_srcdir)/src/3rd/asio/include \
							-I$(top_srcdir)/src/3rd/sqlite \
							-I$(top_srcdir)/src/3rd/rocksdb/include \
							-I$(top_srcdir)/src/3rd/websocketpp \
							-I$(top_srcdir)/src/3rd/openssl/include \
							-I$(top_srcdir)/src/3rd/bzip2 \
							-I$(top_srcdir)/src/3rd/zlib \
							-I$(top_srcdir)/src/3rd/http \
							 $(NULL)
