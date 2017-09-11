#include "test.h"
#include <utils\ecc_sm2.h>
#include <iostream>

void test_sm2() {
	int nTotal = 1000;
	int nSuccess = 0;
	int nFail = 0;
	//for (int i = 0; i < nTotal; i++) {
	//	std::string r, s, xA, yA;
	//	std::string id = "alice";
	//	std::string msg = "hello";

	//	utils::EccSm2 key(utils::EccSm2::GetCFCAGroup());
	//	key.NewRandom();
	//	key.GetPublicKey(xA,yA);
	//	key.Sign(id, msg, r, s);
	//	if (utils::EccSm2::verify(utils::EccSm2::GetCFCAGroup(), xA, yA, id, msg, r, s)) {
	//		nSuccess++;
	//		printf("success:%d\n",nSuccess);
	//	}
	//	else {
	//		nFail++;
	//		printf("fail:%d xA.size=%u yA.size=%u r.size=%u s.size=%u\n", 
	//			nFail, xA.size(), yA.size(), r.size(), s.size());
	//	}
	//}

	printf("test SM2 CFCA GROUP:\n");
	printf("random skey total=%d, success=%d, fail=%d", nTotal, nSuccess, nFail);
	
	EC_GROUP * group = utils::EccSm2::NewGroup(utils::EccSm2::F2M,
		"020000000000000000000000000000000000000000000000000000000000001001",
		"00",
		"00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B",
		"00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD",
		"013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E",
		"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D");
	for (int i = 0; i < 10000;i++)
	{
		std::string r, s, xA, yA;
		std::string id = "alice";
		std::string msg = "hello";
		utils::EccSm2 key(group);
		key.NewRandom();
		key.GetPublicKey(xA, yA);
		key.Sign(id, msg, r, s);
		bool b = utils::EccSm2::verify(group, xA, yA, id, msg, r, s);
		if (b) {
			printf("%d OK\n", i);
		}
		else {
			printf("%d fail\n", i);
		}
	}

}