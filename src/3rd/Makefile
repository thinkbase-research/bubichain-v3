#Compile 3rd party libraries first, some headers are generated after build, say 3rd/openssl/include
ROCKSDB = rocksdb/librocksdb.a
ROCKSDB_PATH = rocksdb

PROTOBUF = protobuf/src/.libs/libprotobuf.a
PROTOBUF_PATH = protobuf

LIBSSL = openssl/libssl.a
LIBSSL_PATH = openssl
LIBCRYPTO = openssl/libcrypto.a

LIBBZ2 = bzip2-1.0.6/libbz2.a
LIBBZ2_PATH = bzip2-1.0.6

LIBZ = zlib-1.2.8/libz.a
LIBZ_PATH = zlib-1.2.8

JSONCPP = jsoncpp/libs/libjson.a
JSONCPP_PATH = jsoncpp

POSTGRE = postgresql-9.4.0/src/interfaces/libpq/libpq.a 
POSTGRE_PATH = postgresql-9.4.0/

CURL = curl/lib/.libs/libcurl.a
CURL_PATH = curl

GTEST = gtest/gtest.a
GTEST_PATH = gtest

PCRE = pcre-8.39/.libs/libpcre.a
PCRE_PATH = pcre-8.39

CUR_DIR = $(shell pwd)

#default libraries target list
$(MONGOC): \
    $(LIBBSON)

all:add_permission\
    $(ROCKSDB) \
    $(PROTOBUF) \
    $(LIBSSL) \
    $(LIBCRYPTO) \
    $(LIBBZ2) \
    $(LIBZ) \
    $(JSONCPP) \
    $(PCRE) \
	$(CURL) \
	$(GTEST)

.PHONY:add_permission
add_permission:
	chmod +x ./protobuf/autogen.sh; \
	chmod +x ./jsoncpp/automake.sh; \
	chmod +x ./rocksdb/build_tools/*; \
	chmod +x ./sqlite/configure; \
	chmod +x ./openssl/config; \
	[-d ./openssl/include] || cd openssl && ./config;

#sub target 
$(ROCKSDB):
	@echo "*************building rocksdb now*************" && cd $(ROCKSDB_PATH) && pwd && $(MAKE) static_lib 
$(PROTOBUF) :
	@echo "*************building protobuf now***************" && cd $(PROTOBUF_PATH) && chmod +x autogen.sh && ./autogen.sh && chmod +x configure && ./configure --prefix=/usr && $(MAKE)
$(LIBSSL) :
	@echo "*************building openssl now ***************" && cd $(LIBSSL_PATH) && chmod +x config && ./config  && $(MAKE)
$(LIBCRYPTO) :
	@echo "*************building openssl now ***************" && cd $(LIBSSL_PATH) && chmod +x config && ./config  && $(MAKE)
$(LIBBZ2) :
	@echo "*************building BZIP2 now ***************" && cd $(LIBBZ2_PATH) && $(MAKE)
$(LIBZ) :
	@echo "*************building LIBZ now ***************" && cd $(LIBZ_PATH) && chmod +x configure && ./configure && $(MAKE)
$(JSONCPP) :
	@echo "*************building jsoncpp now***************" && cd $(JSONCPP_PATH) && ./automake.sh
$(CURL):
	-@echo "**************building curl now***************" && cd $(CURL_PATH) && chmod +x configure && ./configure --disable-ldap --disable-ldaps --without-librtmp --with-ssl=$(CUR_DIR)/openssl && $(MAKE)
$(PCRE):
	@echo "***************building pcre now****************" && cd $(PCRE_PATH) && autoreconf -f -i && chmod +x configure && ./configure && $(MAKE)
$(GTEST):
	@echo "**************building gtest now***************" && cd $(GTEST_PATH) && $(MAKE)

clean:
	@echo "******************skip clean 3rd, you can use 'clean_3rd' if you need******************"
	
clean_3rd: \
    ROCKSDB_clean \
    PROTOBUF_clean \
    LIBSSL_clean \
    LIBCRYPTO_clean \
    LIBBZ2_clean \
    LIBZ_clean \
    JSONCPP_clean \
	CURL_clean \
	PCRE_clean \
	GTEST_clean 
    
install:
	@echo "No library to install for 3rd"
    
ROCKSDB_clean:
	@echo "******************Cleaning rocksdb now*************" && cd $(ROCKSDB_PATH) && make clean
PROTOBUF_clean:
	@echo "******************Cleaning rocksdb now*************" && cd $(PROTOBUF_PATH) && make clean
LIBSSL_clean:
	@echo "******************Cleaning rocksdb now*************" && cd $(LIBSSL_PATH) && make clean
LIBCRYPTO_clean:
	@echo "******************Cleaning rocksdb now*************" && cd $(LIBSSL_PATH) && make clean
LIBBZ2_clean:
	@echo "******************Cleaning rocksdb now*************" && cd $(LIBBZ2_PATH) && make clean
LIBZ_clean:
	@echo "******************Cleaning rocksdb now*************" && cd $(LIBZ_PATH) && make clean
CURL_clean:
	@echo "******************Cleaning curl now*************" && cd $(CURL_PATH) && make clean
PCRE_clean:
	@echo "******************Cleaning pcre now*************" && cd $(PCRE_PATH) && make clean
GTEST_clean:
	@echo "******************Cleaning gtest now*************" && cd $(GTEST_PATH) && make clean

#scon -c may complains error
JSONCPP_clean: 
	@echo "******************Cleaning rocksdb now*************" && cd $(JSONCPP_PATH) && ./automake.sh -c || true   
    
