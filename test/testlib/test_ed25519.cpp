#include <utils/headers.h>
#include <3rd/ed25519-donna/ed25519.h>
#include "test.h"

int TestEd25519(){
	std::string priv_key_str = "6bbe201fe88b5e69c200f05b24f0ffd1aa1af6b45cf97e83aed6142a64caf952";
	//pub  a2696c635db261aa4101f03b5a2d5f4e087e54276ede151e2f9502c6f1dc4afe
	std::string bin_priv = utils::String::HexStringToBin(priv_key_str);

	//ed25519_secret_key priv_key;
	ed25519_public_key pub_key;

	//ed25519_randombytes_unsafe(priv_key, sizeof(priv_key));
	ed25519_publickey((unsigned char *)bin_priv.c_str(), pub_key);

	ed25519_signature sign;
	std::string data = "message";
	ed25519_sign((unsigned char *)data.c_str(), data.size(), (unsigned char *)bin_priv.c_str(), pub_key, sign);
	
	std::string str_sign;
	str_sign.append((char *)sign, sizeof(sign));

	LOG_INFO("signature: %s", utils::String::BinToHexString(str_sign).c_str());

	//std::string a, b;
	//a.append((char *)priv_key, 32);
	//b.append((char *)pub_key, 32);
	//LOG_INFO("%s - %s", utils::String::BinToHexString(a).c_str(), utils::String::BinToHexString(b).c_str());

	return true;
}