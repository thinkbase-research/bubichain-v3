bin_PROGRAMS = monitor_detection
monitor_detection_SOURCES = monitor_detection.cpp
monitor_detection_CXXFLAGS = -std=c++11 \
							 -I$(top_srcdir)/src/3rd/zeromq/zeromq-4.2.1/include \
							 $(NULL)
					  
monitor_detection_LDADD =	\
				$(top_builddir)/src/3rd/zeromq/zeromq-4.2.1/src/.libs/libzmq.a \
				-lpthread -ldl \
				$(NULL)
					
monitor_detection_LDFLAGS = -static -static-libstdc++ -static-libgcc
