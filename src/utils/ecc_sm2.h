/*
Copyright Bubi Technologies Co., Ltd. 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef ECC_SM2_H_
#define ECC_SM2_H_

#include <memory>
#include <limits.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <string>
#ifdef WIN32
#include <winbase.h>
#endif

namespace utils{

    class EccSm2 {
        BIGNUM *dA_;//私钥
        EC_POINT* pkey_;//公钥
        std::string skey_bin_;
        bool valid_;
		std::string error_;
    public:
		enum GROUP_TYPE {
			GFP = 0,
			F2M = 1
		};
		//最大支持1024bit的运算
		const static int MAX_BITS = 128;
        EccSm2(EC_GROUP* group);
        ~EccSm2();

        bool From(std::string skey_bin);
        bool NewRandom();

        //id_bin  用户身份
        //msg_bin 消息(字节流)
        //sigr  签名r部分(字节流)
        //sigs  签名s部分(字节流)
		std::string Sign(const std::string& id_bin, const std::string& msg_bin);
        
		//返回未压缩的公钥
        std::string GetPublicKey();

        //px: 公钥x坐标
        //py: 公钥y坐标
        //msg: 验证的消息
        //id: 用户身份标识
        //r: 签名r
        //s: 签名的s值
		/*static int verify(EC_GROUP* group, const std::string& px, const std::string& py,
			const std::string& id, const std::string& msg, const std::string& r, const std::string&  s);
			*/
		static int verify(EC_GROUP* group, const std::string& pkey,
			const std::string& id, const std::string& msg, const std::string& sig);

		//group 椭圆曲线
		//id  身份
		//pkey  公钥点
		static std::string getZA(EC_GROUP* group, std::string id, const EC_POINT* pkey);

		//返回16进制私钥
        std::string getSkeyHex();

		std::string getSkeyBin();

		//返回CFCA选取的曲线
		//静态变量，不需要释放
		static EC_GROUP* GetCFCAGroup();

		//产生一个新的group. 如果你不知道这句话什么意思，请不要调用它
		//入参分别是 p,a,b,xG,yG,n的16进制格式
		//失败返回NULL 
		//成功返回新的group, 需要手动释放
		static EC_GROUP* NewGroup(GROUP_TYPE type,std::string phex, std::string ahex, std::string bhex, std::string xGhex, std::string yGhex, std::string nhex);

    private:
        EC_GROUP* group_;

		static EC_GROUP* cfca_group_;
    };

}

#endif
