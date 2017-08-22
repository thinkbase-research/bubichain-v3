default_target:release

.PHONY:release debug
release:
	cd build/linux && cmake -DCMAKE_INSTALL_PREFIX=/usr/local ../../src && make

debug:
	cd build/linux && cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=/root/dyz ../../src && make

.PHONY:clean_all clean clean_build clean_3rd
clean_all:clean clean_build clean_3rd

clean:
	rm -rf bin && rm -rf lib

clean_3rd:
	cd src/3rd && make clean_3rd && cd ../../

clean_build:
	rm -rf build/linux/*

.PHONY:install uninstall
install:
	cd build/linux && make install && make soft_link -f MakeSupplement

uninstall:
	cd build/linux && make uninstall -f MakeSupplement

