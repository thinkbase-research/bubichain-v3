noinst_LIBRARIES = libbubi_common.a
libbubi_common_a_CXXFLAGS =  				-std=c++11 -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_ \
							-I$(top_srcdir)/src/3rd/jsoncpp/include \
							-I$(top_srcdir)/src/  \
							-I$(top_srcdir)/src/3rd/protobuf/src/ \
							-I$(top_srcdir)/src/3rd/asio/include \
							-I$(top_srcdir)/src/3rd/sqlite \
							-I$(top_srcdir)/src/3rd/rocksdb/include \
							-I$(top_srcdir)/src/3rd/pcre-8.39 \
							-I$(top_srcdir)/src/3rd/openssl/include \
							-I$(top_srcdir)/src/3rd/bzip2-1.0.6 \
							-I$(top_srcdir)/src/3rd/zlib-1.2.8 \
							-I$(top_srcdir)/src/3rd/http \
							-I$(top_srcdir)/src/3rd/websocketpp \
							$(NULL)

libbubi_common_a_SOURCES = configure_base.cpp \
						general.cpp \
						storage.cpp \
						private_key.cpp \
						daemon.cpp \
						ca_manager.cpp \
						argument.cpp \
						pb2json.cpp \
						cfca.cpp \
						network.cpp 
						
noinst_HEADERS = configure_base.h general.h storage.h private_key.h 

