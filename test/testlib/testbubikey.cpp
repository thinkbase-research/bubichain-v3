#include <common/private_key.h>


void test_bubikey(){


	bubi::PrivateKey skey(bubi::SIGNTYPE_RSA);
	std::string strpkey = skey.GetBase16PublicKey();
	for (int i = 0; i < 10000; i++)
	{
		//bubi::PublicKey pkey(strpkey);
		std::string sig = skey.Sign("hello");
		
		//auto ppp = pkey.GetBase16PublicKey();

		assert(bubi::PublicKey::Verify("hello", sig, strpkey));
		//auto addr1 = skey.GetBase16Address();
		//auto addr2 = pkey.GetBase16Address();
		//assert(addr1 == addr2);
		printf("%d\n", i);
	}


}