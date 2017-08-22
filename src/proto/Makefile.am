noinst_LIBRARIES = libbubi_proto.a

libbubi_proto_a_CXXFLAGS =  -std=c++11 \
							-DASIO_STANDALONE \
							-I$(top_srcdir)/src/3rd/asio/include \
							 -I$(top_srcdir)/src/  \
							 -I$(top_builddir)/src/3rd/protobuf/src/	\
							 -I$(top_builddir)/src/3rd/jsoncpp/include \
							$(NULL)

libbubi_proto_a_SOURCES = cpp/common.pb.cc \
	cpp/consensus.pb.cc \
	cpp/chain.pb.cc \
 	cpp/overlay.pb.cc \
	cpp/merkeltrie.pb.cc \
	cpp/monitor.pb.cc

