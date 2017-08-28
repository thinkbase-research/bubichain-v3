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

#ifndef GENERAL_H_
#define GENERAL_H_

#include <asio.hpp>
#include <utils/headers.h>
#include <json/value.h>
#include <utils/sm3.h>

namespace bubi {
	class General {
	public:
		const static uint32_t OVERLAY_VERSION;
		const static uint32_t OVERLAY_MIN_VERSION;
		const static uint32_t LEDGER_VERSION;
		const static uint32_t LEDGER_MIN_VERSION;
		const static uint32_t MONITOR_VERSION;
		const static char *BUBI_VERSION;

		const static int CONSENSUS_PORT = 9333;
		const static int WEBSERVER_PORT = 19333;

		const static int METADATA_KEY_MAXSIZE = 256;
		const static int METADATA_MAXSIZE = 1048576;
		const static int ASSET_CODE_MAX_SIZE = 64;
		const static int EXPRCONDITION_MAXSIZE = 1048576;

		//contract A can invoke contract B, and contract B can invoke contract C...
		// the max RECURSIVE DEPTH is 4
		const static int CONTRACT_MAX_RECURSIVE_DEPTH = 4;

		//at most 512 transaction can be created when a contract executed
		const static int CONTRACT_TRANSACTION_LIMIT = 512;

		const static int LAST_TX_HASHS_LIMIT = 100;

		const static char *DEFAULT_KEYVALUE_DB_PATH;
		const static char *DEFAULT_ACCOUNT_DB_PATH;

		const static char *DEFAULT_LEDGER_DB_PATH;
		const static char *DEFAULT_RATIONAL_DB_PATH;

		const static char *CONFIG_FILE;
		const static char *MONITOR_CONFIG_FILE;
		const static char *CA_CONFIG_FILE;
		const static char *LOGGER_FILE;

		const static char *CONSENSUS_PREFIX;

		const static char *LEDGER_PREFIX;
		const static char *TRANSACTION_PREFIX;
		const static char *LEDGER_TRANSACTION_PREFIX;
		const static char *CONSENSUS_VALUE_PREFIX;
		const static char *PEERS_TABLE;
		const static char *LAST_TX_HASHS;
		const static char *LAST_PROOF;

		const static int ACCOUNT_LENGTH_MAX = 40;

		const static char *KEY_LEDGER_SEQ;
		const static char *KEY_GENE_ACCOUNT;
		const static char *VALIDATORS;

		const static char *ACCOUNT_PREFIX;
		const static char *ASSET_PREFIX;
		const static char *METADATA_PREFIX;

		const static int32_t TRANSACTION_LIMIT_SIZE;
		const static int32_t TXSET_LIMIT_SIZE;
		const static int32_t ACCOUNT_LIMIT_SIZE;

		typedef enum WARNINGCODE_ {
			WARNING,
			NOWARNING
		} WARNINGCODE;

		volatile static long tx_new_count;
		volatile static long tx_delete_count;
		volatile static long txset_new_count;
		volatile static long txset_delete_count;
		volatile static long peermsg_new_count;
		volatile static long peermsg_delete_count;
		volatile static long account_new_count;
		volatile static long account_delete_count;
		volatile static long trans_low_new_count;
		volatile static long trans_low_delete_count;
	};

	class Result {
		int32_t code_;
		std::string desc_;

	public:
		int64_t ledger_seq_;
		int64_t close_time_;

		Result();
		~Result();

		int32_t code() const;
		std::string desc() const;

		void set_code(int32_t code);
		void set_desc(const std::string desc);

		bool operator=(const Result &result);
	};

	class TimerNotify {
	protected:
		int64_t last_check_time_;
		int64_t last_slow_check_time_;

		int64_t check_interval_;

		int64_t last_execute_complete_time_;
		int64_t last_slow_execute_complete_time_;
		std::string timer_name_;
	public:
		static std::list<TimerNotify *> notifys_;
		static bool RegisterModule(TimerNotify *module) { notifys_.push_back(module); return true; };

		TimerNotify() :last_check_time_(0), last_slow_check_time_(0), check_interval_(0) {};
		~TimerNotify() {};

		void TimerWrapper(int64_t current_time) {
			last_execute_complete_time_ = 0; //clear first
			if (current_time > last_check_time_ + check_interval_) {
				last_check_time_ = current_time;
				OnTimer(current_time);
				last_execute_complete_time_ = utils::Timestamp::HighResolution();
			}
		};

		void SlowTimerWrapper(int64_t current_time) {
			last_slow_execute_complete_time_ = 0;//clear first
			if (current_time > last_slow_check_time_ + check_interval_) {
				last_slow_check_time_ = current_time;
				OnSlowTimer(current_time);
				last_slow_execute_complete_time_ = utils::Timestamp::HighResolution();
			}
		};

		bool IsSlowExpire(int64_t time_out) {
			return last_slow_execute_complete_time_ - last_slow_check_time_ > time_out;
		}

		bool IsExpire(int64_t time_out) {
			return last_execute_complete_time_ - last_check_time_ > time_out;
		}

		int64_t GetSlowLastExecuteTime() {
			return last_slow_execute_complete_time_ - last_slow_check_time_;
		}

		int64_t GetLastExecuteTime() {
			return last_execute_complete_time_ - last_check_time_;
		}

		std::string GetTimerName() {
			return timer_name_;
		}

		virtual void OnTimer(int64_t current_time) = 0;
		virtual void OnSlowTimer(int64_t current_time) = 0;
	};

	class StatusModule {
	public:
		static std::list<StatusModule *> modules_;
		static Json::Value *modules_status_;
		static utils::ReadWriteLock status_lock_;
		static bool RegisterModule(StatusModule *module) { modules_.push_back(module); return true; };
		static void GetModulesStatus(Json::Value &nData);

		StatusModule() {};
		~StatusModule() {};

		virtual void GetModuleStatus(Json::Value &nData) = 0;
	};

	class SlowTimer : public utils::Singleton<bubi::SlowTimer>, public utils::Runnable {
	public:
		SlowTimer();
		~SlowTimer();

		bool Initialize(size_t thread_count);
		bool Exit();

		asio::io_service io_service_;
		//utils::Thread *thread_ptr_;
		std::vector<utils::Thread *> thread_ptrs_;
		virtual void Run(utils::Thread *thread) override;
		void Stop();
	};

	class Global : public utils::Singleton<bubi::Global>, public TimerNotify {
		asio::io_service io_service_;
		asio::io_service::work work_;
		int64_t main_thread_id_;
	public:
		Global();
		~Global();
		bool Initialize();
		bool Exit();
		virtual void OnTimer(int64_t current_time) override;
		virtual void OnSlowTimer(int64_t current_time) override {};
		asio::io_service &GetIoService();
		int64_t GetMainThreadId();
	};

#define  ASSERT_MAIN_THREAD assert(utils::Thread::current_thread_id() == Global::Instance().GetMainThreadId());

	class HashWrapper : public utils::NonCopyable {
		int32_t type_;// 0 : protocol::LedgerUpgrade::SHA256, 1: protocol::LedgerUpgrade::SM3
		utils::Hash *hash_;
	public:
		enum HashType {
			HASH_TYPE_SHA256 = 0,
			HASH_TYPE_SM3 = 1,
			HASH_TYPE_MAX = 2
		};

		HashWrapper();
		HashWrapper(int32_t type);
		~HashWrapper();

		void Update(const std::string &input);
		void Update(const void *buffer, size_t len);
		std::string Final();

		static void SetLedgerHashType(int32_t type);
		static int32_t GetLedgerHashType();

		static std::string Crypto(const std::string &input);
		static void Crypto(unsigned char* str, int len, unsigned char *buf);
		static void Crypto(const std::string &input, std::string &str);
	};

	std::string GetDataSecuretKey();
	std::string ComposePrefix(const std::string &prefix, const std::string &value);
	std::string ComposePrefix(const std::string &prefix, int64_t value);
}

#endif
