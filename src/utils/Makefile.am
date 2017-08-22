noinst_LIBRARIES = libbubi_utils.a

libbubi_utils_a_CXXFLAGS =	-std=c++11 -DASIO_STANDALONE \
							-I$(top_srcdir)/src/3rd/asio/include \
							-I$(top_srcdir)/src/3rd/openssl/include \
							-I$(top_srcdir)/src/3rd/bzip2-1.0.6 \
							-I$(top_srcdir)/src/3rd/zlib-1.2.8 \
							-I$(top_srcdir)/src/3rd/pcre-8.39 \
							-I$(top_srcdir)/src/3rd/http \
							$(NULL)

libbubi_utils_a_SOURCES =	file.cpp \
							logger.cpp \
							net.cpp \
							thread.cpp \
							timestamp.cpp \
							utils.cpp  \
							crypto.cpp \
							lrucache.hpp \
							noncopyable.h \
							timer.cpp \
							timestamp.cpp \
							system.cpp\
							sqlparser.cpp \
							exprparser.cpp \
							ca.cpp \
							sm3.cpp \
							ecc_sm2.cpp \
							$(NULL)

 
