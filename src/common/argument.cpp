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

#include "general.h"
#include "private_key.h"
#include "ca_manager.h"
#include "argument.h"

namespace bubi {
	bool g_enable_ = true;
	Argument::Argument() :
		help_modle_(false), drop_db_(false),
		update_(false), peer_addr_(false),
		del_peer_addr_(false), clear_consensus_status_(false) {}
	Argument::~Argument() {}

	bool Argument::Parse(int argc, char *argv[]) {
		if (argc > 1) {
			std::string s(argv[1]);
			if (s == "--dropdb") {
				drop_db_ = true;
			}
			else if (s == "--update") {
				update_ = true;
			}
			else if (s == "--hardware-address") {
				ShowHardwareAddress();
				return true;
			}
			else if (s == "--request-cert") {
				RequestCert(argc, argv);
				return true;
			}
			else if (s == "--aes-crypto" && argc > 2) {
				printf("%s\n", (utils::Aes::CryptoHex(argv[2], bubi::GetDataSecuretKey())).c_str());
				return true;
			}
			//else if (s == "--aes-decrypt"  && argc > 2) {
			//	printf("%s\n", utils::Aes::HexDecrypto(argv[2], bubi::GetDataSecuretKey()).c_str());
			//	return true;
			//}
			else if (s == "--sm3"  && argc > 2) {
				printf("%s\n", utils::String::BinToHexString(utils::Sm3::Crypto(argv[2])).c_str());
				return true;
			}
			else if (s == "--sm3-hex"  && argc > 2) {
				printf("%s\n", utils::String::BinToHexString(utils::Sm3::Crypto(utils::String::HexStringToBin(argv[2]))).c_str());
				return true;
			}
			else if (s == "--show-request") {
				ShowRequest(argc, argv);
				return true;
			}
			else if (s == "--peer-address") {
				ShowNodeId(argc, argv);
				return true;
			}
			else if (s == "--clear-consensus-status") {
				clear_consensus_status_ = true;
			}
			else if (s == "--version") {
				printf("%s\n", General::BUBI_VERSION);
#ifdef SVNVERSION
				printf("%s; " SVNVERSION "\n", General::BUBI_VERSION);
#endif 
				return true;
			}
			else if (s == "--help") {
				Usage();
				return true;
			}
			else if (s == "--create-account" && argc > 2) {
				SignatureType type = GetSignTypeByDesc(argv[2]);
				if (type == SIGNTYPE_NONE) {
					printf("parameter \"%s\" error, support sm2/ed25519/rsa \n", argv[2]);
					return true;
				} 

				PrivateKey priv_key(type);
				std::string public_key = priv_key.GetBase16PublicKey();
				std::string private_key = priv_key.GetBase16PrivateKey();
				std::string public_address = priv_key.GetBase16Address();

				LOG_TRACE("Creating account address:%s", public_address.c_str());
				Json::Value result = Json::Value(Json::objectValue);
				result["public_key"] = public_key;
				result["private_key"] = private_key;
				result["private_key_aes"] = utils::Aes::CryptoHex(private_key, bubi::GetDataSecuretKey());
				result["address"] = public_address;
				result["public_key_raw"] = utils::String::BinToHexString(priv_key.GetRawPublicKey());
				result["sign_type"] = GetSignTypeDesc(priv_key.GetSignType());
				printf("%s\n", result.toStyledString().c_str());
				return true;
			}
			else if (s == "--dbtool") {
				printf("input database path:\n");
				std::string path;
				std::cin >> path;
				KeyValueDb* ledger_db_ = nullptr;
#ifdef WIN32
				ledger_db_ = new LevelDbDriver();
#else
				ledger_db_ = new RocksDbDriver();
#endif
				if (!ledger_db_->Open(path)) {
					return false;
				}

				printf("1:list all key and values\n");
				printf("2:query one key\n");
				char ch;
				std::cin >> ch;
				if (ch == '1'){
#ifdef WIN32
					auto it = (leveldb::Iterator*)ledger_db_->NewIterator();
#else
					auto it = (rocksdb::Iterator*)ledger_db_->NewIterator();
#endif
					for (it->SeekToFirst(); it->Valid(); it->Next()){
						printf("%s:%s\n", utils::String::BinToHexString(it->key().ToString()).c_str(),
							utils::String::BinToHexString(it->value().ToString()).c_str());
					}
				}
				else if (ch == '2')
					while (true){
						printf("\ninput key(hex):");
						std::string hexkey, buff;
						std::cin >> hexkey;
						auto binkey = utils::String::HexStringToBin(hexkey);
						if (ledger_db_->Get(binkey, buff)){
							printf("%s", utils::String::BinToHexString(buff).c_str());
						}
						else{
							printf("%s", ledger_db_->error_desc().c_str());
						}
					}
				return true;
			}
			else {
				Usage();
				return true;
			}
		}

		return false;
	}

	void Argument::Usage() {
		printf(
			"Usage: bubi [OPTIONS]\n"
			"OPTIONS:\n"
			"  --dropdb                        clean up database\n"
			"  --update                        sync data from remote peers\n"
			"  --peer-address                  get local peer address\n"
			"  --hardware-address              get local hardware address\n"
			"  --request-cert                  request entity certificate\n"
			"  --show-request                  show request certificate\n"
			"  --clear-consensus-status        delete consensus status\n"
			"  --sm3                           generate sm3 hash \n"
			"  --sm3-hex                       generate sm3 hash from hex format \n"
			"  --aes-crypto                    crypto \n"
			"  --version                       display version information\n"
			"  --help                          display this help\n"
			);
	}

	bool Argument::CompleteDbTask( KeyValueDb *key_db) {
		if (drop_db_) {
			return true;
		}

		return false;
	}

	void Argument::ShowNodeId(int argc, char *argv[]) {
		if (argc < 3) {
			printf("missing parameter, need 1 parameter (the aes_crypto code of private key)\n");
			return;
		}

		if (!utils::String::IsHexString(argv[2])) {
			printf("the node_id of inputting is invalid, please check it!\n");
			return;
		}

		bubi::PrivateKey private_key(utils::Aes::HexDecrypto(argv[2], bubi::GetDataSecuretKey()));

		printf("local peer address (%s)\n", private_key.GetBase16Address().c_str());
	}

	void Argument::ShowHardwareAddress() {
		std::string hard_address = "";
		utils::System system;
		char out_msg[256] = { 0 };
		if (system.GetHardwareAddress(hard_address, out_msg))
			printf("local hardware address (%s)\n", hard_address.c_str());
		else
			printf("%s\n", out_msg);
	}

	void Argument::RequestCert(int argc, char *argv[]) {
		if (argc < 8) {
			printf("missing parameter, need 6 parameters (filepath, common_name, organization, email, private_password, hardware_address, node_id(when ignore, it's *)\n");
			return;
		}
		char* node_id = NULL;
		if (8 == argc) {
			node_id = argv[8];
		}

		char out_msg[256] = { 0 };
		bubi::CAManager ca;
		if (!ca.RequestCA(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], node_id, out_msg)) {
			printf("%s\n", out_msg);
		}
	}

	void Argument::ShowRequest(int argc, char *argv[]) {
		// show request certificate
		if (argc < 3) {
			printf("missing parameter, need parameter (request_file_path or request_file_name)\n");
			return;
		}
		bubi::CAManager ca;
		char out_msg[256] = { 0 };
		if (!ca.ShowRequestCSR(argv[2], out_msg)) {
			printf("%s\n", out_msg);
		}
	}

	void SignalFunc(int32_t code) {
		fprintf(stderr, "Get quit signal(%d)\n", code);
		g_enable_ = false;
	}

	void InstallSignal() {
		signal(SIGHUP, SignalFunc);
		signal(SIGQUIT, SignalFunc);
		signal(SIGINT, SignalFunc);
		signal(SIGTERM, SignalFunc);
#ifndef WIN32
		signal(SIGPIPE, SIG_IGN);
#endif
	}

}