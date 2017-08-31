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

#include <utils/headers.h>
#include <common/private_key.h>
#include <common/general.h>
#include <main/configure.h>
#include <overlay/peer_manager.h>
#include <glue/glue_manager.h>
#include "web_server.h"

namespace bubi {

	void WebServer::SubmitTransaction(const http::server::request &request, std::string &reply) {

		Json::Value body;
		if (!body.fromString(request.body)) {
			LOG_ERROR("Parse request body json failed");
			Json::Value reply_json;
			reply_json["results"][Json::UInt(0)]["error_code"] = protocol::ERRCODE_INVALID_PARAMETER;
			reply_json["results"][Json::UInt(0)]["error_desc"] = "request must being json format";
			reply_json["success_count"] = Json::UInt(0);
			reply = reply_json.toStyledString();
			return;
		}

		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value &results = reply_json["results"];
		results = Json::Value(Json::arrayValue);
		uint32_t success_count = 0;

		int64_t begin_time = utils::Timestamp::HighResolution();
		const Json::Value &json_items = body["items"];
		for (size_t j = 0; j < json_items.size() && running; j++) {
			const Json::Value &json_item = json_items[j];
			Json::Value &result_item = results[results.size()];

			int64_t active_time = utils::Timestamp::HighResolution();
			Result result;
			result.set_code(protocol::ERRCODE_SUCCESS);
			result.set_desc("");

			protocol::TransactionEnv tran_env;
			do {
				if (json_item.isMember("transaction_blob")) {
					if (!json_item.isMember("signatures")) {
						result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
						result.set_desc("'signatures' value not exist");
						break;
					}

					std::string decodeblob;
					std::string decodesig;
					//utils::decode_b16(json_item["transaction_blob"].asString(), decodeblob);
					decodeblob;// = utils::String::HexStringToBin(json_item["transaction_blob"].asString());
					if (!utils::String::HexStringToBin(json_item["transaction_blob"].asString(), decodeblob)) {
						result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
						result.set_desc("'transaction_blob' value must be Hex");
						break;
					}

					protocol::Transaction *tran = tran_env.mutable_transaction();
					if (!tran->ParseFromString(decodeblob)) {
						result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
						result.set_desc("ParseFromString from 'sign_data' invalid");
						LOG_ERROR("ParseFromString from decodeblob invalid");
						break;
					}

					const Json::Value &signatures = json_item["signatures"];
					for (uint32_t i = 0; i < signatures.size(); i++) {
						const Json::Value &signa = signatures[i];
						protocol::Signature *signpro = tran_env.add_signatures();

						//utils::decode_b16(signa["sign_data"].asString(), decodesig);
						decodesig = "";
						if (!utils::String::HexStringToBin(signa["sign_data"].asString(), decodesig)) {
							result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
							result.set_desc("'sign_data' value must be Hex");
							break;
						}

						PublicKey pubkey(signa["public_key"].asString());
						if (!pubkey.IsValid()) {
							result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
							result.set_desc("'public_key' value not exist or parameter error");
							LOG_ERROR("Invalid publickey (%s)", signa["public_key"].asString().c_str());
							break;
						}

						signpro->set_sign_data(decodesig);
						signpro->set_public_key(pubkey.GetBase16PublicKey());
					}

					// add node signature
					std::string content = tran->SerializeAsString();
					PrivateKey privateKey(bubi::Configure::Instance().p2p_configure_.node_private_key_);
					if (!privateKey.IsValid()) {
						result.set_code(protocol::ERRCODE_INVALID_PRIKEY);
						result.set_desc("signature failed");
						break;
					}
					std::string sign = privateKey.Sign(content);
					protocol::Signature *signpro = tran_env.add_signatures();
					signpro->set_sign_data(sign);
					signpro->set_public_key(privateKey.GetBase16PublicKey());
					result_item["hash"] = utils::String::BinToHexString(HashWrapper::Crypto(content));
				}
				else {
					protocol::Transaction *tran = tran_env.mutable_transaction();
		
					Json2Proto(json_item["transaction_json"], *tran);
	

					std::string content = tran->SerializeAsString();
					const Json::Value &private_keys = json_item["private_keys"];
					for (uint32_t i = 0; i < private_keys.size(); i++) {
						const std::string &private_key = private_keys[i].asString();

						PrivateKey privateKey(private_key);
						if (!privateKey.IsValid()) {
							result.set_code(protocol::ERRCODE_INVALID_PRIKEY);
							result.set_desc("signature failed");
							break;
						}

						std::string sign = privateKey.Sign(content);
						protocol::Signature *signpro = tran_env.add_signatures();
						signpro->set_sign_data(sign);
						signpro->set_public_key(privateKey.GetBase16PublicKey());
					}

					// add node signature
					PrivateKey privateKey(bubi::Configure::Instance().p2p_configure_.node_private_key_);
					if (!privateKey.IsValid()) {
						result.set_code(protocol::ERRCODE_INVALID_PRIKEY);
						result.set_desc("signature failed");
						break;
					}
					std::string sign = privateKey.Sign(content);
					protocol::Signature *signpro = tran_env.add_signatures();
					signpro->set_sign_data(sign);
					signpro->set_public_key(privateKey.GetBase16PublicKey());
					result_item["hash"] = utils::String::BinToHexString(HashWrapper::Crypto(content));
				}

				TransactionFrm frm(tran_env);
				if (!frm.CheckValid(-1)){
					result = frm.result_;
					break;
				}

			} while (false);

			if (result.code() == protocol::ERRCODE_SUCCESS) {
				success_count++;
				TransactionFrm::pointer ptr = std::make_shared<TransactionFrm>(tran_env);
				GlueManager::Instance().OnTransaction(ptr, result);
				PeerManager::Instance().Broadcast(protocol::OVERLAY_MSGTYPE_TRANSACTION, tran_env.SerializeAsString());
			}
			result_item["error_code"] = result.code();
			result_item["error_desc"] = result.desc();
		}
		LOG_TRACE("Create %u transaction use " FMT_I64 "(ms)", json_items.size(),
			(utils::Timestamp::HighResolution() - begin_time) / utils::MICRO_UNITS_PER_MILLI);


		reply_json["success_count"] = success_count;
		reply = reply_json.toStyledString();
	}

	void WebServer::CreateAccount(const http::server::request &request, std::string &reply) {
		std::string error_desc;
		int32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);
		
		SignatureType sign_type = SIGNTYPE_CFCASM2;

		do {
			std::string sign_type_s = request.GetParamValue("sign_type");
			if (sign_type_s == ""){
				if (HashWrapper::GetLedgerHashType()) {
					sign_type = SIGNTYPE_ED25519;
				}
				else {
					sign_type = SIGNTYPE_CFCASM2;
				}
			}
			else {
				sign_type = GetSignTypeByDesc(sign_type_s);
				if (sign_type == SIGNTYPE_NONE) {
					error_code = protocol::ERRCODE_INVALID_PARAMETER;
					break;
				} 
			}

			PrivateKey priv_key(sign_type);
			std::string public_key = priv_key.GetBase16PublicKey();
			std::string private_key = priv_key.GetBase16PrivateKey();
			std::string public_address = priv_key.GetBase16Address();

			LOG_TRACE("Creating account address:%s", public_address.c_str());

			Json::Value &result = reply_json["result"];
			result["public_key"] = public_key;
			result["private_key"] = private_key;
			result["private_key_aes"] = utils::Aes::CryptoHex(private_key, bubi::GetDataSecuretKey());
			result["address"] = public_address;
			result["public_key_raw"] = utils::String::BinToHexString(priv_key.GetRawPublicKey());
			result["sign_type"] = GetSignTypeDesc(sign_type);

		} while (false);
		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}

	void WebServer::ConfValidator(const http::server::request &request, std::string &reply) {
		std::string error_desc;
		int32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);

		do {
			if (!request.peer_address_.IsLoopback()) {
				error_code = protocol::ERRCODE_ACCESS_DENIED;
				error_desc = "This url should be called from local";
				break;
			}

			std::string add = request.GetParamValue("add");
			std::string del = request.GetParamValue("del");

			Result ret = GlueManager::Instance().ConfValidator(add, del);
			error_code = ret.code();
			error_desc = ret.desc();
		} while (false);

		reply_json["error_code"] = error_code;
		reply_json["error_desc"] = error_desc;
		reply = reply_json.toStyledString();
	}
}