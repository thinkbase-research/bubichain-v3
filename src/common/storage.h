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

#ifndef STORAGE_H_
#define STORAGE_H_

#include <unordered_map>
#include <utils/headers.h>
#include <utils/sqlparser.h>
#include <json/json.h>
#include "general.h"
#include "configure_base.h"
#ifdef WIN32
#include <leveldb/leveldb.h>
#else
#include <rocksdb/db.h>
#endif

namespace bubi {
#ifdef WIN32
#define KVDB leveldb
#define WRITE_BATCH leveldb::WriteBatch
#define WRITE_BATCH_DATA(batch) (((std::string*)(&batch))->c_str())
#define WRITE_BATCH_DATA_SIZE(batch) (((std::string*)(&batch))->size())
#define SLICE       leveldb::Slice
#else 
#define KVDB rocksdb
#define WRITE_BATCH rocksdb::WriteBatch
#define WRITE_BATCH_DATA(batch) (batch.Data().c_str())
#define WRITE_BATCH_DATA_SIZE(batch) (batch.GetDataSize())
#define SLICE       rocksdb::Slice
#endif

	class KeyValueDb {
	protected:
		utils::Mutex mutex_;
		std::string error_desc_;
	public:
		KeyValueDb();
		~KeyValueDb();
		virtual bool Open(const std::string &db_path) = 0;
		virtual bool Close() = 0;
		virtual int32_t Get(const std::string &key, std::string &value) = 0;
		virtual bool Put(const std::string &key, const std::string &value) = 0;
		virtual bool Delete(const std::string &key) = 0;
		virtual bool GetOptions(Json::Value &options) = 0;
		std::string error_desc() {
			return error_desc_;
		}
		virtual bool WriteBatch(WRITE_BATCH &values) = 0;

		virtual void* NewIterator() = 0;
	};

#ifdef WIN32
	class LevelDbDriver : public KeyValueDb {
	private:
		leveldb::DB* db_;

	public:
		LevelDbDriver();
		~LevelDbDriver();

		bool Open(const std::string &db_path);
		bool Close();
		int32_t Get(const std::string &key, std::string &value);
		bool Put(const std::string &key, const std::string &value);
		bool Delete(const std::string &key);
		bool GetOptions(Json::Value &options);
		bool WriteBatch(WRITE_BATCH &values);

		void* NewIterator();
	};
#else
	class RocksDbDriver : public KeyValueDb {
	private:
		rocksdb::DB* db_;

	public:
		RocksDbDriver();
		~RocksDbDriver();

		bool Open(const std::string &db_path);
		bool Close();
		int32_t Get(const std::string &key, std::string &value);
		bool Put(const std::string &key, const std::string &value);
		bool Delete(const std::string &key);
		bool GetOptions(Json::Value &options);
		bool WriteBatch(WRITE_BATCH &values);

		void* NewIterator();
	};
#endif

	class Storage : public utils::Singleton<bubi::Storage>, public TimerNotify {
		friend class utils::Singleton<Storage>;
	private:
		Storage();
		~Storage();

		KeyValueDb *keyvalue_db_;
		KeyValueDb *ledger_db_;
		KeyValueDb *account_db_;

		bool CloseDb();
		bool DescribeTable(const std::string &name, const std::string &sql_create_table);
		bool ManualDescribeTables();

		KeyValueDb *NewKeyValueDb(const DbConfigure &db_config);
	public:
		bool Initialize(const DbConfigure &db_config, bool bdropdb);
		bool Exit();

		KeyValueDb *keyvalue_db();   //storage others
		KeyValueDb *account_db();   //storage account tree
		KeyValueDb *ledger_db();    //storage transaction and ledger

		virtual void OnTimer(int64_t current_time) {};
		virtual void OnSlowTimer(int64_t current_time);
	};
}

#endif