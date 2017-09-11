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

#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>


namespace utils {
	//typedef std::vector<unsigned char>  std::string;

	std::string Char2Hex(std::string &blob);

	class Base58 {
	public:
		Base58() {}
		~Base58() {}

		//static std::string Encode(unsigned char*buff, int len, std::string& strOut);
		//static std::string Encode(unsigned char*begin, unsigned char *end);

		static std::string Encode(const std::string &buff);

		//static std::string Encode(std::string buff) {
		//	std::string str;
		//	return Base58::Encode(buff, str);
		//}

		//static int Decode(std::string strIn, unsigned char *out);
		static int Decode(const std::string &strIn, std::string &out);
		static int Decode_old(const std::string &strIn, std::string &out);
		static std::string Decode(const std::string &strIn) {
			std::string out = "";
			Decode(strIn, out);
			return out;
		}
	};

	uint8_t Crc8(uint8_t *ptr, uint16_t len);
	uint8_t Crc8(const std::string &data);

	class Hash {
	public:
		Hash() {};
		~Hash() {};

		virtual void Update(const std::string &input) = 0;
		virtual void Update(const void *buffer, size_t len) = 0;
		virtual std::string Final() = 0;
	};

	class Sha256 : public Hash {
		SHA256_CTX ctx_;
	public:
		Sha256();
		~Sha256();

		void Update(const std::string &input);
		void Update(const void *buffer, size_t len);
		std::string Final();

		static std::string CryptoBase58(const std::string &input) {
			return utils::Base58::Encode(Crypto(input));
		}

		static std::string Crypto(const std::string &input);
		static void Crypto(unsigned char* str, int len, unsigned char *buf);

		static void Crypto(const std::string &input, std::string &str);
		//static void Crypto(unsigned char* str1, int len1, unsigned char *str2, int len2, unsigned char *buf);
		//static void Crypto(unsigned char* str1, int len1, unsigned char* str2, int len2, unsigned char *str3, int len3, unsigned char *buf);
	public:
		static const int SIZE = 32;
	};

	class MD5 {
	public:
		static std::string GenerateMd5File(const char* filename);
		static std::string GenerateMd5File(std::FILE* file);

		static std::string GenerateMD5(const void* dat, size_t len);
		static std::string GenerateMD5(std::string dat);

		static std::string GenerateMD5Sum6(const void* dat, size_t len);
		static std::string GenerateMD5Sum6(std::string dat);

	private:
		static char hb2hex(unsigned char hb);
		static void md5bin(const void* dat, size_t len, unsigned char out[16]);
	};



	class Aes {
	public:
		Aes() {};
		~Aes() {};
		static std::string Crypto(const std::string &input, const std::string &key);
		static std::string Decrypto(const std::string &input, const std::string &key);
		static std::string CryptoHex(const std::string &input, const std::string &key);
		static std::string HexDecrypto(const std::string &input, const std::string &key);
	};
}

#endif //CRYPTO_H

