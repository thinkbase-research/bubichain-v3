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

#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/ripemd.h>
#include <utils/logger.h>
#include <utils/crypto.h>
#include <utils/sm3.h>
#include <utils/strings.h>
#include "general.h"
#include "private_key.h"
#include "cfca.h"

namespace bubi {

	bool GetKeyElement(const std::string &base16_pub_key, PrivateKeyPrefix &prefix, SignatureType &sign_type, std::string &raw_data) {
		std::string buff = utils::String::HexStringToBin(base16_pub_key);
		if (buff.size() < 3) {
			return false;
		}

		uint8_t a = (uint8_t)buff.at(0);
		uint8_t b= (uint8_t)buff.at(1);
		//check sum
		PrivateKeyPrefix prefix_tmp = (PrivateKeyPrefix)a;
		SignatureType sign_type_tmp = (SignatureType)b;
		size_t datalen = buff.size() - 3;
		uint8_t checksum = (uint8_t)buff.back();
		uint8_t calc_checksum = utils::Crc8((uint8_t *)buff.c_str(), buff.length() - 1);
		if (checksum != calc_checksum){
			return false;
		}

		bool ret = true;
		if (prefix_tmp == ADDRESS_PREFIX) {
			switch (sign_type_tmp) {
			case SIGNTYPE_ED25519:{
				ret = (ED25519_ADDRESS_LENGTH == datalen);
				break;
			}
			case SIGNTYPE_CFCASM2:{
				ret = (SM2_ADDRESS_LENGTH == datalen);
				break;
			}
			case SIGNTYPE_RSA:{
				break;
			}
			case SIGNTYPE_CFCA:{
				break;
			}
			default:
				ret = false;
			}
		}
		else if (prefix_tmp == PUBLICKEY_PREFIX) {
			switch (sign_type_tmp) {
			case SIGNTYPE_ED25519:{
				ret = (ED25519_PUBLICKEY_LENGTH == datalen);
				break;
			}
			case SIGNTYPE_CFCASM2:{
				ret = (SM2_PUBLICKEY_LENGTH == datalen);
				break;
			}
			case SIGNTYPE_RSA:{
				break;
			}
			case SIGNTYPE_CFCA:{
				break;
			}
			default:
				ret = false;
			}
		}
		else if (prefix_tmp == PRIVATEKEY_PREFIX) {
			switch (sign_type_tmp) {
			case SIGNTYPE_ED25519:{
				ret = (ED25519_PRIVATEKEY_LENGTH == datalen);
				break;
			}
			case SIGNTYPE_CFCASM2:{
				ret = (SM2_PRIVATEKEY_LENGTH == datalen);
				break;
			}
			case SIGNTYPE_RSA:{
				break;
			}
			case SIGNTYPE_CFCA:{
				break;
			}
			default:
				ret = false;
			}
		}
		else {
			ret = false;
		}

		if (ret){
			prefix = prefix_tmp;
			sign_type = sign_type_tmp;
			raw_data = buff.substr(2, buff.size() - 3);
		} 

		return ret;
	}

	std::string GetSignTypeDesc(SignatureType type) {
		switch (type) {
		case SIGNTYPE_CFCA: return "cfca";
		case SIGNTYPE_CFCASM2: return "sm2";
		case SIGNTYPE_RSA: return "rsa";
		case SIGNTYPE_ED25519: return "ed25519";
		}

		return "";
	}

	SignatureType GetSignTypeByDesc(const std::string &desc) {
		if (desc == "cfca") {
			return SIGNTYPE_CFCA;
		}
		else if (desc == "sm2") {
			return SIGNTYPE_CFCASM2;
		}
		else if (desc == "rsa") {
			return SIGNTYPE_RSA;
		}
		else if (desc == "ed25519") {
			return SIGNTYPE_ED25519;
		}

		return SIGNTYPE_NONE;
	}

	PublicKey::PublicKey() :valid_(false), type_(SIGNTYPE_RSA) {}

	PublicKey::~PublicKey() {}

	PublicKey::PublicKey(const std::string &base16_pub_key) {
		do {
			PrivateKeyPrefix prefix;
			valid_ = GetKeyElement(base16_pub_key, prefix, type_, raw_pub_key_);
			valid_ = (prefix == PUBLICKEY_PREFIX);
		} while (false);
	}

	void PublicKey::Init(std::string rawpkey) {
		raw_pub_key_ = rawpkey;
	}

	bool PublicKey::IsAddressValid(const std::string &address_base16) {
		std::string address = utils::String::HexStringToBin(address_base16, true);
		do {
			if (address.size() != 23) {
				break;
			}

			if (address.at(0) != (char)ADDRESS_PREFIX) {
				break;
			} 

			uint8_t crc = utils::Crc8(address.substr(0, address.size()- 1));
			if (crc != (uint8_t)address.back()) {
				break;
			} 

			return true;
		} while (false);

		return false;
	}

	std::string PublicKey::CalcHash(const std::string &value) const {
		std::string hash;
		if (type_ == SIGNTYPE_CFCASM2) {
			hash = utils::Sm3::Crypto(raw_pub_key_);
		}
		else {
			hash = utils::Sha256::Crypto(raw_pub_key_);
		}
		return hash;
	}

	std::string PublicKey::GetBase16Address() const {
		//append prefix
		std::string str_result = "";
		str_result.push_back((char)ADDRESS_PREFIX);

		//append version
		str_result.push_back((char)type_);

		//append public key
		std::string hash = CalcHash(raw_pub_key_);
		str_result.append(hash.substr(12));

		//append check sum
		str_result.push_back((char)utils::Crc8(str_result));
		return utils::String::BinToHexString(str_result);
	}

	std::string PublicKey::GetRawPublicKey() const {
		return raw_pub_key_;
	}

	std::string PublicKey::GetBase16PublicKey() const {
		//append prefix
		std::string str_result = "";
		str_result.push_back((char)PUBLICKEY_PREFIX);

		//append version
		str_result.push_back((char)type_);

		//append public key
		str_result.append(raw_pub_key_);

		str_result.push_back((char)utils::Crc8(str_result));
		return utils::String::BinToHexString(str_result);
	}

	bool PublicKey::Verify(const std::string &data, const std::string &signature, const std::string &public_key_base16) {
		PrivateKeyPrefix prefix;
		SignatureType sign_type;
		std::string raw_pubkey;
		bool valid = GetKeyElement(public_key_base16, prefix, sign_type, raw_pubkey);
		if (!valid || prefix != PUBLICKEY_PREFIX) {
			return false;
		} 

		if (sign_type == SIGNTYPE_ED25519 ) {
			return ed25519_sign_open((unsigned char *)data.c_str(), data.size(), (unsigned char *)raw_pubkey.c_str(), (unsigned char *)signature.c_str()) == 0;
		}
		else if (sign_type == SIGNTYPE_CFCASM2) {
			return utils::EccSm2::verify(utils::EccSm2::GetCFCAGroup(), raw_pubkey, "1234567812345678", data, signature) == 1;
		}
		else if (sign_type == SIGNTYPE_RSA) {
			bool result = false;
			const unsigned char *key_cstr = (const unsigned char *)raw_pubkey.c_str();
			int key_len = raw_pubkey.length();
			//RSA* p_rsa = d2i_RSAPublicKey(NULL, &key_cstr, tmp.length());
			RSA* p_rsa = d2i_RSA_PUBKEY(NULL, &key_cstr, raw_pubkey.length());

			if (p_rsa != NULL) {
				const char *cstr = data.c_str();
				unsigned char hash[SHA_DIGEST_LENGTH] = { 0 };
				SHA1((unsigned char *)cstr, data.length(), hash);
				unsigned char sign_cstr[256] = { 0 };
				memcpy(sign_cstr, signature.c_str(), signature.length());
				int len = signature.length();
				int r = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH, (unsigned char *)sign_cstr, len, p_rsa);
				if (r > 0) {
					result = true;
				}
			}

			RSA_free(p_rsa);
			return result;
		}
		else if (sign_type == SIGNTYPE_CFCA) {
			return cfca::CFCA::Instance().Verify(data, signature, raw_pubkey);
		}
		return false;
	}

	//地址是否合法
	PrivateKey::PrivateKey(SignatureType type) {
		std::string tmp = "";
		type_ = type;
		if (type_ == SIGNTYPE_ED25519) {
			utils::MutexGuard guard_(lock_);
			// ed25519;
			raw_priv_key_.resize(32);
			ed25519_randombytes_unsafe((void*)raw_priv_key_.c_str(), 32);

			tmp.resize(32);
			ed25519_publickey((const unsigned char*)raw_priv_key_.c_str(), (unsigned char*)tmp.c_str());
		}
		else if (type_ == SIGNTYPE_CFCASM2) {
			utils::EccSm2 key(utils::EccSm2::GetCFCAGroup());
			key.NewRandom();
			raw_priv_key_ = key.getSkeyBin();
			tmp = key.GetPublicKey();
		}
		else if (type_ == SIGNTYPE_RSA) {
			RSA *rsa = RSA_new();
			BIGNUM* e = BN_new();
			BN_rand(e, 1022, 1, 1);
			if (!RSA_generate_key_ex(rsa, 1024, e, NULL)) {
				assert(false);
			}
			unsigned char* out = NULL;
			int nLen = i2d_RSAPrivateKey(rsa, &out);
			raw_priv_key_.append((const char*)out, nLen);
			OPENSSL_free(out);

			unsigned char *pkeys = NULL;
			//int plen = i2d_RSAPublicKey(rsa, &pkeys);
			int plen = i2d_RSA_PUBKEY(rsa, &pkeys);
			tmp.append((char*)pkeys, plen);
			OPENSSL_free(pkeys);

			BN_free(e);
			RSA_free(rsa);
		}
		pub_key_.Init(tmp);
		pub_key_.type_ = type_;
		pub_key_.valid_ = true;
		valid_ = true;
	}

	PrivateKey::~PrivateKey() {}

	bool PrivateKey::From(const std::string &base16_private_key) {
		valid_ = false;
		std::string tmp;

		do {
			PrivateKeyPrefix prefix;
			std::string raw_pubkey;
			valid_ = GetKeyElement(base16_private_key, prefix, type_, raw_priv_key_);
			if (!valid_ || prefix != PRIVATEKEY_PREFIX) {
				return false;
			}

			if (type_ == SIGNTYPE_ED25519) {
				tmp.resize(32);
				ed25519_publickey((const unsigned char*)raw_priv_key_.c_str(), (unsigned char*)tmp.c_str());
			}
			else if (type_ == SIGNTYPE_CFCASM2) {
				utils::EccSm2 skey(utils::EccSm2::GetCFCAGroup());
				skey.From(raw_priv_key_);
				tmp = skey.GetPublicKey();
			}
			else if (type_ == SIGNTYPE_RSA) {
				RSA* rsa = NULL;
				const unsigned char* buff = (const unsigned char*)raw_priv_key_.c_str();
				d2i_RSAPrivateKey(&rsa, &buff, raw_priv_key_.length());

				unsigned char* out = NULL;
				//int outlen = i2d_RSAPublicKey(rsa, &out);
				int outlen = i2d_RSA_PUBKEY(rsa, &out);
				tmp.append((const char*)out, outlen);
				OPENSSL_free(out);
				RSA_free(rsa);
			}
			//ToBase58();
			pub_key_.type_ = type_;
			pub_key_.Init(tmp);
			pub_key_.valid_ = true;
			valid_ = true;

		} while (false);
		return valid_;
	}

	PrivateKey::PrivateKey(const std::string &base58_private_key) {
		From(base58_private_key);
	}

	std::string PrivateKey::CalcHash(const std::string &value) const {
		std::string hash;
		if (type_ == SIGNTYPE_ED25519) {
			hash = utils::Sha256::Crypto(value);
		}
		else {
			hash = utils::Sm3::Crypto(value);
		}
		return hash;
	}

	std::string PrivateKey::Sign(const std::string &input) const {
		unsigned char sig[10240];
		unsigned int sig_len = 0;

		if (type_ == SIGNTYPE_ED25519) {
			/*	ed25519_signature sig;*/
			ed25519_sign((unsigned char *)input.c_str(), input.size(), (const unsigned char*)raw_priv_key_.c_str(), (unsigned char*)pub_key_.GetRawPublicKey().c_str(), sig);
			sig_len = 64;
		}
		else if (type_ == SIGNTYPE_CFCASM2) {
			utils::EccSm2 key(utils::EccSm2::GetCFCAGroup());
			key.From(raw_priv_key_);
			std::string r, s;
			return key.Sign("1234567812345678", input);
		}
		else if (type_ == SIGNTYPE_RSA) {
			const unsigned char *key_cstr = (const unsigned char *)raw_priv_key_.c_str();
			int key_len = raw_priv_key_.length();

			RSA *p_rsa = d2i_RSAPrivateKey(NULL, &key_cstr, key_len);

			if (p_rsa != NULL) {

				const char *cstr = input.c_str();
				unsigned char hash[SHA_DIGEST_LENGTH] = { 0 };
				SHA1((unsigned char *)cstr, input.length(), hash);
				int r = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sig, &sig_len, p_rsa);
			}

			RSA_free(p_rsa);
		}
		std::string output;
		output.append((const char *)sig, sig_len);
		return output;
	}

	std::string PrivateKey::GetBase16PrivateKey() const {
		//append prefix
		std::string str_result;
		str_result.push_back((char)PRIVATEKEY_PREFIX);

		//append version
		str_result.push_back((char)type_);

		//append private key
		str_result.append(raw_priv_key_);

		str_result.push_back((char)utils::Crc8(str_result));
		return utils::String::BinToHexString(str_result);
	}

	std::string PrivateKey::GetBase16Address() const {
		return pub_key_.GetBase16Address();
	}

	std::string PrivateKey::GetBase16PublicKey() const {
		return pub_key_.GetBase16PublicKey();
	}

	std::string PrivateKey::GetRawPublicKey() const {
		return pub_key_.GetRawPublicKey();
	}

	utils::Mutex PrivateKey::lock_;
}
