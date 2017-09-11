bin_PROGRAMS = bubid
bubid_SOURCES = main.cpp
bubid_CXXFLAGS = -std=c++11 \
					  $(NULL)
bubid_LDADD =	$(top_builddir)/src/3rd/openssl/libssl.a \
				$(top_builddir)/src/3rd/openssl/libcrypto.a \
				-lpthread -ldl \
				$(NULL)
					
