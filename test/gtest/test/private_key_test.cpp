#if 0
#include <gtest/gtest.h>
#include "common/private_key.h"
#include <utils/crypto.h>
#include <utils/strings.h>

class PrivateKeyTest :public testing::Test
{
protected:
	virtual void SetUp()
	{
		priv_key = new bubi::PrivateKey(bubi::ED25519SIG);
	}
	virtual void TearDown()
	{
		delete priv_key;
		priv_key = NULL;
	}

	bubi::PrivateKey* priv_key;
};

//测试PrivateKey类返回公私钥和地址不为空
TEST_F(PrivateKeyTest, KeyNotNULL){

	EXPECT_TRUE(priv_key->IsValid());
	EXPECT_STRNE("", priv_key->GetBase58PublicKey().c_str());
	EXPECT_STRNE("", priv_key->GetBase58PrivateKey().c_str());
	EXPECT_STRNE("", priv_key->GetBase58Address().c_str());
};

//测试PrivateKey类使用带参构建函数创建的对象返回的公司钥和地址不为空
TEST_F(PrivateKeyTest,PrivateKey2){
	bubi::PrivateKey priv_key2(priv_key->GetBase58PrivateKey());
	EXPECT_TRUE(priv_key2.IsValid());
	EXPECT_STRNE("", priv_key2.GetBase58PublicKey().c_str());
	EXPECT_STRNE("", priv_key2.GetBase58PrivateKey().c_str());
	EXPECT_STRNE("", priv_key2.GetBase58Address().c_str());
};

//测试签名
TEST_F(PrivateKeyTest, Sign){
	EXPECT_STRNE("", priv_key->Sign("").c_str());
};

//测试验证
TEST_F(PrivateKeyTest, Verify){
	std::string data="Hello";
	std::string signature;
	//生成公私钥匙
	ed25519_secret_key raw_priv_key_;
	ed25519_public_key raw_pub_key_;
	ed25519_randombytes_unsafe(raw_priv_key_, sizeof(raw_priv_key_));
	ed25519_publickey(raw_priv_key_, raw_pub_key_);
	//签名
	ed25519_signature sig;
	ed25519_sign((unsigned char *)data.c_str(), data.size(), raw_priv_key_, raw_pub_key_, sig);
	signature.append((const char *)sig, sizeof(sig));

	//对公钥进行base58编码
	std::string key;
	key.append((const char *)raw_pub_key_, sizeof(raw_pub_key_));
	std::string publicKey = utils::Base58::Encode(key);
	//执行测试验证
	EXPECT_TRUE(false);
	EXPECT_TRUE(bubi::PublicKey::Verify(data, signature, publicKey));
	EXPECT_FALSE(bubi::PublicKey::Verify(data + "1", signature, publicKey));
	EXPECT_FALSE(bubi::PublicKey::Verify(data, signature + "1", publicKey));
//	EXPECT_FALSE(bubi::PublicKey::Verify(data, signature, publicKey + "1"));
	//EXPECT_FALSE(bubi::PublicKey::Verify(data, signature,""));
	EXPECT_FALSE(bubi::PublicKey::Verify(data, "", publicKey));
	EXPECT_FALSE(bubi::PublicKey::Verify("", signature, publicKey));
	std::string data2 = "hello";
	std::string signature2 = signature;
	std::string publicKey2 = publicKey;
	signature2.erase(1, 2);
	signature2 += "a";
	publicKey2.erase(1, 2);
	publicKey2 += "a";
	EXPECT_FALSE(bubi::PublicKey::Verify(data2, signature, publicKey));
	EXPECT_FALSE(bubi::PublicKey::Verify(data, signature2, publicKey));
	EXPECT_FALSE(bubi::PublicKey::Verify(data, signature, publicKey2));
}

//测试PublicKey类中方法
TEST_F(PrivateKeyTest, PublicKey){
	bubi::PublicKey pub;
	EXPECT_TRUE(bubi::PublicKey::IsAddressValid(priv_key->GetBase58Address()));
	EXPECT_FALSE(pub.IsValid());
}


TEST(Base58Test, Base58){
	std::string message = "qwertyuiopasdfghjklzxcvbnm1234567890!@#$%^&*()-=[];',./_+{}:\"<>?\\|*-+`~";
	std::string enMessage;
	std::string deMessage;
	enMessage=utils::Base58::Encode(message);
	utils::Base58::Decode(enMessage, deMessage);
	EXPECT_STREQ(deMessage.c_str(), message.c_str());
}
#endif