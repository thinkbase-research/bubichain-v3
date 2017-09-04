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
#include <common/storage.h>
#include <main/configure.h>
#include <ledger/ledger_manager.h>
#include <consensus/consensus_manager.h>
#include <glue/glue_manager.h>
#include "web_server.h"
#include <ledger/kv_trie.h>

namespace bubi {
	void WebServer::GetAccount(const http::server::request &request, std::string &reply) {
		std::string address = request.GetParamValue("address");
		std::string storagekey = request.GetParamValue("key");

		std::string issuer = request.GetParamValue("issuer");
		std::string code = request.GetParamValue("code");

		int32_t error_code = protocol::ERRCODE_SUCCESS;
		AccountFrm::pointer acc = NULL;
		int64_t balance = 0;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value record = Json::Value(Json::arrayValue);
		Json::Value &result = reply_json["result"];

		if (!Environment::AccountFromDB(address, acc)) {
			error_code = protocol::ERRCODE_NOT_EXIST;
			LOG_TRACE("GetAccount fail, account(%s) not exist", address.c_str());
		}
		else {
			acc->ToJson(result);
			Json::Value& metadatas = result["metadatas"];
			if (!storagekey.empty()){
				protocol::KeyPair value_ptr;
				if (acc->GetMetaData(storagekey, value_ptr)){
					metadatas[(Json::UInt)0] = bubi::Proto2Json(value_ptr);
				}
			}
			else{
				std::vector<protocol::KeyPair> metadata;
				acc->GetAllMetaData(metadata);

				for (size_t i = 0; i < metadata.size(); i++){
					metadatas[i] = Proto2Json(metadata[i]);
				}
			}

			Json::Value& jsonassets = result["assets"];
			if (!issuer.empty() && !code.empty()){
				protocol::AssetProperty p;
				p.set_issuer(issuer);
				p.set_code(code);
				protocol::Asset asset;
				if (acc->GetAsset(p, asset)){
					jsonassets[(Json::UInt)0] = Proto2Json(asset);
				}
			}
			else{
				std::vector<protocol::Asset> assets;
				acc->GetAllAssets(assets);
				for (size_t i = 0; i < assets.size(); i++){
					jsonassets[i] = Proto2Json(assets[i]);
				}
			}
		}

		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}


	void WebServer::GetGenesisAccount(const http::server::request &request, std::string &reply){
		std::string address;
		Storage::Instance().account_db()->Get(bubi::General::KEY_GENE_ACCOUNT, address);
		http::server::request req;
		req.parameter.insert({ std::string("address"), address });
		GetAccount(req, reply);
	}

	void WebServer::GetAccountMetaData(const http::server::request &request, std::string &reply){
		std::string address = request.GetParamValue("address");
		std::string metadata_key = request.GetParamValue("key");
		int32_t error_code = protocol::ERRCODE_SUCCESS;
		AccountFrm::pointer acc = NULL;
		int64_t balance = 0;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value record = Json::Value(Json::arrayValue);
		Json::Value &result = reply_json["result"];

		if (!Environment::AccountFromDB(address, acc)) {
			error_code = protocol::ERRCODE_NOT_EXIST;
			LOG_TRACE("account(%s) not exist", address.c_str());
		}
		else {
			if (!metadata_key.empty()){
				protocol::KeyPair value_ptr;
				if (acc->GetMetaData(metadata_key, value_ptr)){
					result[metadata_key] = bubi::Proto2Json(value_ptr);
				}
			}
			else{
				std::vector<protocol::KeyPair> metadata;
				acc->GetAllMetaData(metadata);
				for (size_t i = 0; i < metadata.size(); i++){
					result[metadata[i].key()] = Proto2Json(metadata[i]);
				}
			}
		}

		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}

	void WebServer::Debug(const http::server::request &request, std::string &reply){
		std::string key = request.GetParamValue("key");
		auto location = utils::String::HexStringToBin(key);
		std::vector<std::string> values;
		auto x = LedgerManager::Instance().tree_->GetNode(location);
		Json::Value ret;
		ret["ret"] = bubi::Proto2Json(x);
		ret["NEW"] = NodeFrm::NEWCOUNT;
		ret["DEL"] = NodeFrm::DELCOUNT;

		reply = ret.toStyledString();
	}
	void WebServer::GetAccountAssets(const http::server::request &request, std::string &reply) {
		std::string address = request.GetParamValue("address");

		std::string issuer = request.GetParamValue("issuer");
		std::string code = request.GetParamValue("code");

		int32_t error_code = protocol::ERRCODE_SUCCESS;
		AccountFrm::pointer acc = NULL;
		int64_t balance = 0;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value record = Json::Value(Json::arrayValue);
		Json::Value &result = reply_json["result"];

		if (!Environment::AccountFromDB(address, acc)) {
			error_code = protocol::ERRCODE_NOT_EXIST;
			LOG_TRACE("GetAccount fail, account(%s) not exist", address.c_str());
		}
		else {

			if (!issuer.empty() && !code.empty()){
				protocol::AssetProperty p;
				p.set_issuer(issuer);
				p.set_code(code);
				protocol::Asset asset;
				if (acc->GetAsset(p, asset)){
					result["asset"] = Proto2Json(asset);
				}
			}
			else{
				std::vector<protocol::Asset> assets;
				acc->GetAllAssets(assets);
				for (size_t i = 0; i < assets.size(); i++){
					result[i] = Proto2Json(assets[i]);
				}
			}
		}

		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}

	void WebServer::GetTransactionBlob(const http::server::request &request, std::string &reply) {
		Result result;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value &js_result = reply_json["result"];
		do {
			Json::Value body;
			if (!body.fromString(request.body)) {
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc("");
				break;
			}

			protocol::Transaction tran;
			if (!Json2Proto(body, tran)){
				break;
			}

			std::string SerializeString;
			if (!tran.SerializeToString(&SerializeString)) {
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc("");
				LOG_INFO("SerializeToString Transaction Failed");
				break;
			}

			std::string crypto = utils::encode_b16(SerializeString);
			js_result["transaction_blob"] = crypto;
			js_result["hash"] = utils::encode_b16(HashWrapper::Crypto(SerializeString));
		} while (false);

		reply_json["error_code"] = result.code();
		reply_json["error_desc"] = result.desc();
		reply = reply_json.toStyledString();
	}

	void WebServer::GetTransactionFromBlob(const http::server::request &request, std::string &reply) {
		Result result_e;
		result_e.set_code(protocol::ERRCODE_SUCCESS);
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value &result = reply_json["result"];

		std::string blob = request.GetParamValue("blob");
		std::string env = request.GetParamValue("env");
		do {
			std::string decodeblob;
			if (!utils::String::HexStringToBin(blob, decodeblob)) {
				result_e.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result_e.set_desc("'transaction_blob' value must be Hex");
				break;
			}

			protocol::TransactionEnv tran_env;
			if (env == "true"){
				if (!tran_env.ParseFromString(decodeblob)) {
					result_e.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					result_e.set_desc("Parse From env String from decodeblob invalid");
					LOG_ERROR("ParseFromString from decodeblob invalid");
					break;
				}
			}
			else{
				protocol::Transaction *tran = tran_env.mutable_transaction();
				if (!tran->ParseFromString(decodeblob)) {
					result_e.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					result_e.set_desc("Parse From String from decodeblob invalid");
					LOG_ERROR("ParseFromString from decodeblob invalid");
					break;
				}
			}

			TransactionFrm frm(tran_env);
			frm.ToJson(reply_json);

		} while (false);

		reply_json["error_code"] = result_e.code();
		reply_json["error_desc"] = result_e.desc();
		reply = reply_json.toStyledString();
	}

	void WebServer::GetExprResult(const http::server::request &request, std::string &reply){
		Result result;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value &js_result = reply_json["result"];

		std::string parse = request.GetParamValue("parse");
		do {

			ExprCondition parser(request.body);
			utils::ExprValue value;
			if (parse == "true"){
				result = parser.Parse(value);
			}
			else{
				result = parser.Eval(value);
				js_result["value"] = value.Print();
			}

		} while (false);

		reply_json["error_code"] = result.code();
		reply_json["error_desc"] = result.desc();
		reply = reply_json.toStyledString();
	}

	void WebServer::GetTransactionHistory(const http::server::request &request, std::string &reply) {
		WebServerConfigure &web_config = Configure::Instance().webserver_configure_;
		bubi::KeyValueDb *db = bubi::Storage::Instance().ledger_db();

		std::string seq = request.GetParamValue("ledger_seq");
		std::string hash = request.GetParamValue("hash");
		std::string start = request.GetParamValue("start");
		std::string limit = request.GetParamValue("limit");

		int32_t start_int = utils::String::Stoi(start);
		int32_t limit_int = utils::String::Stoi(limit);

		if (start_int < 0) start_int = 0;
		if (limit_int <= 0) limit_int = 1000;

		int32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);

		Json::Value &result = reply_json["result"];
		Json::Value &txs = result["transactions"];
		txs = Json::Value(Json::arrayValue);
		result["total_count"] = 0;
		do {

			protocol::EntryList list;
			//avoid scan the whole table
			protocol::LedgerHeader header = LedgerManager::Instance().GetLastClosedLedger();
			if (!seq.empty()) {
				std::string hashlist;
				if (db->Get(ComposePrefix(General::LEDGER_TRANSACTION_PREFIX, seq), hashlist) <= 0) {
					error_code = protocol::ERRCODE_NOT_EXIST;
					break;
				}

				list.ParseFromString(hashlist);
				if (list.entry_size() == 0) {
					error_code = protocol::ERRCODE_NOT_EXIST;
					break;
				}

				result["total_count"] = list.entry_size();
			}
			else if (!hash.empty()) {
				result["total_count"] = 1;
				list.add_entry(utils::String::HexStringToBin(hash));
			}
			else {
				std::string hashlist;
				if (db->Get(General::LAST_TX_HASHS, hashlist) <= 0) {
					error_code = protocol::ERRCODE_NOT_EXIST;
					break;
				}

				list.ParseFromString(hashlist);
				if (list.entry_size() == 0) {
					error_code = protocol::ERRCODE_NOT_EXIST;
					break;
				}

				result["total_count"] = list.entry_size();
			}

			for (int32_t i = start_int; 
				i < list.entry_size() &&
				error_code == protocol::ERRCODE_SUCCESS &&
				i < start_int + limit_int; 
				i++) {
				TransactionFrm txfrm;
				if (txfrm.LoadFromDb(list.entry(i)) > 0) {
					result["total_count"] = 0;
					error_code = protocol::ERRCODE_NOT_EXIST;
					break;
				}
				Json::Value m;
				txfrm.ToJson(m);
				txs[txs.size()] = m;
			}
		} while (false);

		reply_json["error_code"] = error_code;
		reply = reply_json.toFastString();
	}


	void WebServer::GetContractTx(const http::server::request &request, std::string &reply) {
		WebServerConfigure &web_config = Configure::Instance().webserver_configure_;

		std::string hash = request.GetParamValue("hash");
		std::string contractor = request.GetParamValue("contractor");
		std::string trigger = request.GetParamValue("trigger");

		std::string str_order = request.GetParamValue("order");
		std::string start_str = request.GetParamValue("start");
		std::string limit_str = request.GetParamValue("limit");

		if (str_order == "DESC" ||
			str_order == "desc" ||
			str_order == "asc" ||
			str_order == "ASC") {
		}
		else {
			str_order = "DESC";
		}

		int32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);

		Json::Value &result = reply_json["result"];
		Json::Value &txs = result["transactions"];
		txs = Json::Value(Json::arrayValue);
		do
		{
			if (start_str.empty()) start_str = "0";
			if (!utils::String::is_number(start_str) == 1){
				error_code = protocol::ERRCODE_INVALID_PARAMETER;
				break;
			}
			uint32_t start = utils::String::Stoui(start_str);


			if (limit_str.empty()) limit_str = "20";
			if (!utils::String::is_number(limit_str) == 1){
				error_code = protocol::ERRCODE_INVALID_PARAMETER;
				break;
			}
			uint32_t limit = utils::String::Stoui(limit_str);
			limit = MIN(limit, web_config.query_limit_);


			std::string condition = "WHERE 1=1 ";
			if (!hash.empty())
				condition += utils::String::Format("AND hash='%s' ", hash.c_str());

			if (!contractor.empty())
				condition += utils::String::Format("AND contractor='%s' ", contractor.c_str());

			if (!trigger.empty())
				condition += utils::String::Format("AND trigger_transaction='%s' ", trigger.c_str());
			Json::Value record;

			for (size_t i = 0; i < record.size() && error_code == protocol::ERRCODE_SUCCESS; i++) {

				Json::Value &item = record[i];
				protocol::Transaction prototx;
				prototx.ParseFromString(utils::String::HexStringToBin(item["body"].asString()));
				Json::Value m = item;
				m["body"] = Proto2Json(prototx);

				txs[(Json::UInt) i] = m;
			}
		} while (false);
		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}


	void WebServer::GetStatus(const http::server::request &request, std::string &reply) {
		uint32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value &result = reply_json["result"];

		const protocol::LedgerHeader &ledger = LedgerManager::Instance().GetLastClosedLedger();
		result["transaction_count"] = ledger.tx_count();
		result["account_count"] = LedgerManager::Instance().GetAccountNum();

		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}


	void WebServer::GetModulesStatus(const http::server::request &request, std::string &reply) {
		utils::ReadLockGuard guard(bubi::StatusModule::status_lock_);
		Json::Value reply_json = *bubi::StatusModule::modules_status_;

		reply_json["keyvalue_db"] = Json::Value(Json::objectValue);
		bubi::Storage::Instance().keyvalue_db()->GetOptions(reply_json["keyvalue_db"]);
		reply_json["ledger_db"] = Json::Value(Json::objectValue);
		bubi::Storage::Instance().ledger_db()->GetOptions(reply_json["ledger_db"]);
		reply_json["account_db"] = Json::Value(Json::objectValue);
		bubi::Storage::Instance().account_db()->GetOptions(reply_json["account_db"]);

		reply = reply_json.toStyledString();
	}

	void WebServer::GetLedgerValidators(const http::server::request &request, std::string &reply) {
		int32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value &result = reply_json["result"];

		std::string ledger_seq = request.GetParamValue("seq");
		if (ledger_seq.empty())
			ledger_seq = utils::String::ToString(LedgerManager::Instance().GetLastClosedLedger().seq());

		protocol::ValidatorSet set;
		if (!LedgerManager::Instance().GetValidators(utils::String::Stoi64(ledger_seq), set)) {
			error_code = protocol::ERRCODE_NOT_EXIST;
		}
		else {
			result = Proto2Json(set);
		}

		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}

	void WebServer::GetLedger(const http::server::request &request, std::string &reply) {
		std::string ledger_seq = request.GetParamValue("seq");
		std::string with_validator = request.GetParamValue("with_validator");
		std::string with_consvalue = request.GetParamValue("with_consvalue");


		/// default last closed ledger
		if (ledger_seq.empty())
			ledger_seq = utils::String::ToString(LedgerManager::Instance().GetLastClosedLedger().seq());


		int32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value record = Json::Value(Json::arrayValue);
		Json::Value &result = reply_json["result"];

		LedgerFrm frm;
		do
		{
			int64_t seq = utils::String::Stoi64(ledger_seq);
			if (!frm.LoadFromDb(seq)) {
				error_code = protocol::ERRCODE_NOT_EXIST;
				break;
			}
			result = frm.ToJson();

			if (with_validator == "true") {
				protocol::ValidatorSet set;
				if (LedgerManager::Instance().GetValidators(seq, set)) {
					Json::Value validator = Proto2Json(set);
					result["validators"] = validator["validators"];
				}
				else {
					error_code = protocol::ERRCODE_NOT_EXIST;
					break;
				}
			}

			if (with_consvalue == "true") {
				protocol::ConsensusValue cons;
				if (LedgerManager::Instance().ConsensusValueFromDB(seq, cons)) {
					result["consensus_value"] = Proto2Json(cons);
				}
				else {
					error_code = protocol::ERRCODE_NOT_EXIST;
					break;
				}

				Json::Value &json_cons = result["consensus_value"];
				protocol::PbftProof pbft_evidence;
				if (!pbft_evidence.ParseFromString(cons.previous_proof())) {
					error_code = protocol::ERRCODE_INTERNAL_ERROR;
					break;
				}

				json_cons["previous_proof_plain"] = Proto2Json(pbft_evidence);
			}
		} while (false);


		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}

	void WebServer::GetConsensusInfo(const http::server::request &request, std::string &reply) {
		Json::Value root;
		ConsensusManager::Instance().GetConsensus()->GetModuleStatus(root);
		reply = root.toStyledString();
	}

	void WebServer::GetAddress(const http::server::request &request, std::string &reply) {
		std::string private_key = request.GetParamValue("private_key");
		std::string public_key = request.GetParamValue("public_key");
		Json::Value reply_json = Json::Value(Json::objectValue);

		if (!private_key.empty()){
			PrivateKey key(private_key);
			if (key.IsValid()) {
				reply_json["error_code"] = protocol::ERRCODE_SUCCESS;
				Json::Value &result = reply_json["result"];
				result["public_key"] = key.GetBase16PublicKey();
				result["private_key"] = key.GetBase16PrivateKey();
				result["address"] = key.GetBase16Address();
				result["private_raw"] = key.GetRawPrivateKey();
				result["public_key_raw"] = utils::String::BinToHexString(key.GetRawPublicKey());
				result["sign_type"] = GetSignTypeDesc(key.GetSignType());
			}
			else {
				reply_json["error_code"] = protocol::ERRCODE_INVALID_PARAMETER;
			}
		}
		else if (!public_key.empty()){
			PublicKey key(public_key);
			if (key.IsValid()) {
				reply_json["error_code"] = protocol::ERRCODE_SUCCESS;
				Json::Value &result = reply_json["result"];
				result["public_key"] = key.GetBase16PublicKey();
				result["address"] = key.GetBase16Address();
				result["sign_type"] = GetSignTypeDesc(key.GetSignType());
			}
			else {
				reply_json["error_code"] = protocol::ERRCODE_INVALID_PARAMETER;
			}
		}
		else{
			reply_json["error_code"] = protocol::ERRCODE_INVALID_PARAMETER;
		}

		reply = reply_json.toStyledString();
	}

	void WebServer::GetPeerNodeAddress(const http::server::request &request, std::string &reply){
		std::string token = request.GetParamValue("token");
		if (token != "bubiokqwer") {
			reply = "Access is not valid";
			return;
		}

		bubi::PrivateKey priv_key(bubi::Configure::Instance().p2p_configure_.node_private_key_);
		if (priv_key.IsValid()){
			reply = utils::String::Format("%s", priv_key.GetBase16Address().c_str());
		}
		else{
			reply = "address not exist";
		}
	}

	static bool AssetAmountSorter(std::pair < std::string, int64_t> const& ac1, std::pair < std::string, int64_t> const& ac2)
	{
		// need to use the hash of whole tx here since multiple txs could have
		// the same Contents
		return ac1.second > ac2.second;
	}

	void WebServer::GetPeerAddresses(const http::server::request &request, std::string &reply) {
		uint32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);

		do {
			std::string peers;
			KeyValueDb *db = Storage::Instance().keyvalue_db();
			int32_t count = db->Get(General::PEERS_TABLE, peers);
			if (count < 0) {
				LOG_ERROR("Load peers info from db failed, error desc(%s)", db->error_desc().c_str());
				error_code = protocol::ERRCODE_INTERNAL_ERROR;
				break;
			}

			if (count == 0) {
				LOG_ERROR("Load peers info from db failed, not initialize");
				break;
			}

			protocol::Peers all;
			if (!all.ParseFromString(peers)) {
				LOG_ERROR("Parse peers string failed");
				break;
			}

			Json::Value &result = reply_json["result"];
			result = Proto2Json(all);
		} while (false);

		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}

#if 0
	void WebServer::GetSignature(const http::server::request &request, std::string &reply) {

		uint32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);

		std::string strBody = request.body;
		Json::Value body;
		body.fromString(strBody);
		std::string prikey = body["private_key"].asString();
		std::string str_blob = body["transaction_blob"].asString();

		do {
			PrivateKey key(prikey);
			if (!key.IsValid()) {
				error_code = protocol::ERRCODE_INVALID_PRIKEY;
				break;
			}
			std::string blob_decode;
			utils::decode_b16(str_blob, blob_decode);

			std::string strOut = key.Sign(blob_decode);
			if (strOut.empty()) {
				error_code = protocol::ERRCODE_INTERNAL_ERROR;
			}

			Json::Value &result = reply_json["result"];

			result["signature"] = utils::encode_b16(strOut);
			//PublicKey pkey = key.GetPublicKey();
			result["public_key"] = key.GetBase16PublicKey();

		} while (false);

		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}

	void WebServer::GetAccountTree(const http::server::request &request, std::string &reply) {
		//Json::Value jsonRoot, stat;
		//auto tree = LedgerManager::Instance().tree_;
		//int n = 0;
		//tree->(nullptr, 0, jsonRoot, stat, n, true);
		//reply = jsonRoot.toStyledString();
	}
#endif
}