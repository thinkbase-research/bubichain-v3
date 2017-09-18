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

#include <utils/logger.h>
#include <utils/sm3.h>
#include "general.h"
#include "utils/strings.h"
#include "proto/cpp/common.pb.h"

namespace bubi {
	const uint32_t General::OVERLAY_VERSION = 2000;
	const uint32_t General::OVERLAY_MIN_VERSION = 2000;
	const uint32_t General::LEDGER_VERSION = 3000;
	const uint32_t General::LEDGER_MIN_VERSION = 3000;
	const uint32_t General::MONITOR_VERSION = 3000;
	const char *General::BUBI_VERSION = "3.0.0.1";

#ifdef WIN32
	const char *General::DEFAULT_KEYVALUE_DB_PATH = "data/keyvalue.db";
	const char *General::DEFAULT_LEDGER_DB_PATH = "data/ledger.db";
	const char *General::DEFAULT_ACCOUNT_DB_PATH = "data/account.db";
	
	const char *General::DEFAULT_RATIONAL_DB_PATH = "data/rational.db";
	const char *General::CONFIG_FILE = "config/bubi.json";
	const char *General::MONITOR_CONFIG_FILE = "config/monitor.json";
	const char *General::CA_CONFIG_FILE = "config/ca.json";
	const char *General::LOGGER_FILE = "log/bubi.log";

#else
	const char *General::DEFAULT_KEYVALUE_DB_PATH = "data/keyvalue.db";
	const char *General::DEFAULT_LEDGER_DB_PATH = "data/ledger.db";
	const char *General::DEFAULT_ACCOUNT_DB_PATH = "data/account.db";

	const char *General::DEFAULT_RATIONAL_DB_PATH = "bubidata/rational.db";
	const char *General::CONFIG_FILE = "config/bubi.json";
	const char *General::CA_CONFIG_FILE = "config/ca.json";
	const char *General::LOGGER_FILE = "log/bubi.log";
#endif

	volatile long General::tx_new_count = 0;
	volatile long General::tx_delete_count = 0;
	volatile long General::txset_new_count = 0;
	volatile long General::txset_delete_count = 0;
	volatile long General::peermsg_new_count = 0;
	volatile long General::peermsg_delete_count = 0;
	volatile long General::account_new_count = 0;
	volatile long General::account_delete_count = 0;
	volatile long General::trans_low_new_count = 0;
	volatile long General::trans_low_delete_count = 0;

	const char *General::STATISTICS = "statistics";
	const char *General::KEY_LEDGER_SEQ = "max_seq";
	const char *General::KEY_GENE_ACCOUNT = "genesis_account";
	const char *General::VALIDATORS = "validators";
	const char *General::PEERS_TABLE = "peers";
	const char *General::LAST_TX_HASHS = "last_tx_hashs";
	const char *General::LAST_PROOF = "last_proof";

	const char *General::CONSENSUS_PREFIX = "consensus";

	const char *General::LEDGER_PREFIX = "ldg";
	const char *General::TRANSACTION_PREFIX = "tx";
	const char *General::LEDGER_TRANSACTION_PREFIX = "lgtx";
	const char *General::CONSENSUS_VALUE_PREFIX = "cosv";

	const char *General::ACCOUNT_PREFIX = "acc";
	const char *General::ASSET_PREFIX = "ast";
	const char *General::METADATA_PREFIX = "meta";

	const int32_t General::TRANSACTION_LIMIT_SIZE = 4 * utils::BYTES_PER_MEGA;
	const int32_t General::TXSET_LIMIT_SIZE = 32 * utils::BYTES_PER_MEGA;
	const int32_t General::ACCOUNT_LIMIT_SIZE = 16 * utils::BYTES_PER_MEGA;


	Result::Result(){
		code_ = protocol::ERRCODE_SUCCESS;
	}

	Result::~Result(){};

	int32_t Result::code() const{
		return code_;
	}

	std::string Result::desc() const{
		return desc_;
	}

	void Result::set_code(int32_t code){
		code_ = code;
	}

	void Result::set_desc(const std::string desc){
		desc_ = desc;
	}

	bool Result::operator=(const Result &result){
		code_ = result.code();
		desc_ = result.desc();
		return true;
	}

	std::list<StatusModule *> StatusModule::modules_;
	Json::Value *StatusModule::modules_status_ = NULL;
	utils::ReadWriteLock StatusModule::status_lock_;

	void StatusModule::GetModulesStatus(Json::Value &nData){
		for (auto &item : modules_) {
			Json::Value json_item = Json::Value(Json::objectValue);
			int64_t begin_time = utils::Timestamp::HighResolution();
			item->GetModuleStatus(json_item);
			json_item["time"] = utils::String::Format(FMT_I64 " ms", (utils::Timestamp::HighResolution() - begin_time) / utils::MICRO_UNITS_PER_MILLI);
			std::string key = json_item["name"].asString();
			json_item.removeMember("name");
			nData[key] = json_item;
		}
	}

	std::list<TimerNotify *> TimerNotify::notifys_;

	SlowTimer::SlowTimer(){
	}

	SlowTimer::~SlowTimer(){}

	bool SlowTimer::Initialize(size_t thread_count){
		for (size_t i = 0; i < thread_count; i++){
			utils::Thread *thread_p = new utils::Thread(this);
			if (!thread_p->Start(utils::String::Format("slowtimer-%d", i))){
				return false;
			}

			thread_ptrs_.push_back(thread_p);
		}

		return true;
	}

	bool SlowTimer::Exit(){
		LOG_INFO("SlowTimer stoping...");
		io_service_.stop();
		for (size_t i = 0; i < thread_ptrs_.size(); i++){
			utils::Thread *thread_p = thread_ptrs_[i];
			if (thread_p){
				thread_p->JoinWithStop();
				delete thread_p;
				thread_p = NULL;
			}
		}
		LOG_INFO("SlowTimer stop [OK]");
		return true;
	}

	void SlowTimer::Run(utils::Thread *thread){
		asio::io_service::work work(io_service_);
		while (!io_service_.stopped()){
			asio::error_code err;
			io_service_.poll(err);

			for (auto item : TimerNotify::notifys_){
				item->SlowTimerWrapper(utils::Timestamp::HighResolution());

				if (item->IsSlowExpire(5 * utils::MICRO_UNITS_PER_SEC)){
					LOG_WARN("The timer(%s) execute time(" FMT_I64 " us) is expire than 5s", item->GetTimerName().c_str(), item->GetSlowLastExecuteTime());
				}
			}

			utils::Sleep(1);
		}
	}

	Global::Global() : work_(io_service_), main_thread_id_(0){
	}

	Global::~Global(){
	}

	bool Global::Initialize(){
		timer_name_ = "Global";
		main_thread_id_ = utils::Thread::current_thread_id();
		TimerNotify::RegisterModule(this);
		return true;
	}

	bool Global::Exit(){
		LOG_INFO("Global stoping...");
		LOG_INFO("Global stop [OK]");
		return true;
	}

	void Global::OnTimer(int64_t current_time){
		//clock_.crank(false);
		asio::error_code err;
		io_service_.poll(err);
	}

	asio::io_service &Global::GetIoService(){
		return io_service_;
	}

	int64_t Global::GetMainThreadId(){
		return main_thread_id_;
	}
	
	static int32_t ledger_type_ = HashWrapper::HASH_TYPE_SHA256;
	HashWrapper::HashWrapper(){
		type_ = ledger_type_;
		if (type_ == HASH_TYPE_SM3){
			hash_ = new utils::Sm3();
		}
		else{
			hash_ = new utils::Sha256();
		}
	}

	HashWrapper::HashWrapper(int32_t type){
		type_ = type;
		if (type_ == HASH_TYPE_SM3){
			hash_ = new utils::Sm3();
		}
		else{
			hash_ = new utils::Sha256();
		}
	}

	HashWrapper::~HashWrapper(){
		if (hash_){
			delete hash_;
		} 
	}

	void HashWrapper::Update(const std::string &input){
		hash_->Update(input);
	}

	void HashWrapper::Update(const void *buffer, size_t len){
		hash_->Update(buffer, len);
	}

	std::string HashWrapper::Final(){
		return hash_->Final();
	}

	void HashWrapper::SetLedgerHashType(int32_t type_){
		ledger_type_ = type_;
	}

	int32_t HashWrapper::GetLedgerHashType(){
		return ledger_type_;
	}

	std::string HashWrapper::Crypto(const std::string &input){
		if (ledger_type_ == HASH_TYPE_SM3){
			return utils::Sm3::Crypto(input);
		}
		else{
			return utils::Sha256::Crypto(input);
		}
	}

	void HashWrapper::Crypto(unsigned char* str, int len, unsigned char *buf){
		if (ledger_type_ == HASH_TYPE_SM3){
			utils::Sm3::Crypto(str, len, buf);
		}
		else{
			utils::Sha256::Crypto(str, len, buf);
		}
	}

	void HashWrapper::Crypto(const std::string &input, std::string &str){
		if (ledger_type_ == HASH_TYPE_SM3){
			utils::Sm3::Crypto(input, str);
		}
		else{
			utils::Sha256::Crypto(input, str);
		}
	}

	std::string ComposePrefix(const std::string &prefix, const std::string &value) {
		std::string result = prefix;
		result += "_";
		result += value;
		return result;
	}

	std::string ComposePrefix(const std::string &prefix, int64_t value) {
		std::string result = prefix;
		result += "_";
		result += utils::String::ToString(value);
		return result;
	}
}
