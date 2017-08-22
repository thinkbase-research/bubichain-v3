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

#ifndef CONFIGURE_BASE_H_
#define CONFIGURE_BASE_H_

#include <json/json.h>
#include <utils/singleton.h>
#include <utils/strings.h>
#include <utils/net.h>

namespace bubi {

	class LoggerConfigure {
	public:
		LoggerConfigure();
		~LoggerConfigure();

		std::string path_;
		std::string dest_str_;
		std::string level_str_;
		int32_t time_capacity_;
		int64_t size_capacity_;

		uint32_t dest_;
		uint32_t level_;
		int32_t expire_days_;
		bool Load(const Json::Value &value);
	};

	class DbConfigure {
	public:
		DbConfigure();
		~DbConfigure();

		std::string keyvalue_db_path_;
		std::string ledger_db_path_;
		std::string account_db_path_;
		std::string rational_string_;
		std::string rational_db_type_;
		std::string tmp_path_;
		bool async_write_sql_;
		bool async_write_kv_;
		bool Load(const Json::Value &value);
	};

	class SSLConfigure {
	public:
		SSLConfigure();
		~SSLConfigure();

		std::string chain_file_;
		std::string private_key_file_;
		std::string private_password_;
		std::string dhparam_file_;
		std::string verify_file_;

		bool Load(const Json::Value &value);
	};

	class ConfigureBase  {
	public:
		ConfigureBase();
		~ConfigureBase();

	public:

		virtual bool Load(const std::string &config_file_path);
		virtual bool LoadFromJson(const Json::Value &value) { return false; };

		static void GetValue(const Json::Value &object, const std::string &key, std::string &value);
		static void GetValue(const Json::Value &object, const std::string &key, int32_t &value);
		static void GetValue(const Json::Value &object, const std::string &key, uint32_t &value);
		static void GetValue(const Json::Value &object, const std::string &key, int64_t &value);
		static void GetValue(const Json::Value &object, const std::string &key, utils::StringList &list);
		static void GetValue(const Json::Value &object, const std::string &key, bool &value);
	};
}

#endif