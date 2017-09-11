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

#include <pcrecpp.h>
#include <utils/strings.h>
#include <utils/logger.h>
#include <utils/file.h>
#include "storage.h"
#include "general.h"

namespace bubi {
	KeyValueDb::KeyValueDb() {}

	KeyValueDb::~KeyValueDb() {}

#ifdef WIN32
	LevelDbDriver::LevelDbDriver() {
		db_ = NULL;
	}

	LevelDbDriver::~LevelDbDriver() {
		if (db_ != NULL) {
			delete db_;
			db_ = NULL;
		}
	}

	bool LevelDbDriver::Open(const std::string &db_path) {
		leveldb::Options options;
		options.create_if_missing = true;
		leveldb::Status status = leveldb::DB::Open(options, db_path, &db_);
		if (!status.ok()) {
			utils::MutexGuard guard(mutex_);
			error_desc_ = status.ToString();
		}
		return status.ok();
	}

	bool LevelDbDriver::Close() {
		delete db_;
		db_ = NULL;
		return true;
	}

	int32_t LevelDbDriver::Get(const std::string &key, std::string &value) {
		assert(db_ != NULL);
		leveldb::Status status = db_->Get(leveldb::ReadOptions(), key, &value);
		if (status.ok()) {
			return 1;
		}
		else if(status.IsNotFound()) {
			return 0;
		}
		else {
			utils::MutexGuard guard(mutex_);
			error_desc_ = status.ToString();
			return -1;
		}
	}

	bool LevelDbDriver::Put(const std::string &key, const std::string &value) {
		assert(db_ != NULL);
		leveldb::WriteOptions opt;
		opt.sync = true;
		leveldb::Status status = db_->Put(opt, key, value);
		if (!status.ok()) {
			utils::MutexGuard guard(mutex_);
			error_desc_ = status.ToString();
		}
		return status.ok();
	}

	bool LevelDbDriver::Delete(const std::string &key) {
		assert(db_ != NULL);
		leveldb::Status status = db_->Delete(leveldb::WriteOptions(), key);
		if (!status.ok()) {
			error_desc_ = status.ToString();
		}
		return status.ok();
	}

	bool LevelDbDriver::WriteBatch(WRITE_BATCH &write_batch) {

		leveldb::WriteOptions opt;
		opt.sync = true;
		leveldb::Status status = db_->Write(opt, &write_batch);
		if (!status.ok()) {
			utils::MutexGuard guard(mutex_);
			error_desc_ = status.ToString();
		}
		return status.ok();
	}

	void* LevelDbDriver::NewIterator() {
		return db_->NewIterator(leveldb::ReadOptions());
	}

	bool LevelDbDriver::GetOptions(Json::Value &options) {
		return true;
	}

#else

	RocksDbDriver::RocksDbDriver() {
		db_ = NULL;
	}

	RocksDbDriver::~RocksDbDriver() {
		if (db_ != NULL) {
			delete db_;
			db_ = NULL;
		}
	}

	bool RocksDbDriver::Open(const std::string &db_path) {
		rocksdb::Options options;
		options.create_if_missing = true;
		// Optimize RocksDB. This is the easiest way to get RocksDB to perform well
		long cpus = sysconf(_SC_NPROCESSORS_ONLN);
		options.IncreaseParallelism(cpus);
		//options.OptimizeLevelStyleCompaction();
		rocksdb::Status status = rocksdb::DB::Open(options, db_path, &db_);
		if (!status.ok()) {
			utils::MutexGuard guard(mutex_);
			error_desc_ = status.ToString();
		}
		return status.ok();
	}

	bool RocksDbDriver::Close() {
		delete db_;
		db_ = NULL;
		return true;
	}

	int32_t RocksDbDriver::Get(const std::string &key, std::string &value) {
		assert(db_ != NULL);
		rocksdb::Status status = db_->Get(rocksdb::ReadOptions(), key, &value);
		if (status.ok()) {
			return 1;
		}
		else if (status.IsNotFound()) {
			return 0;
		}
		else {
			utils::MutexGuard guard(mutex_);
			error_desc_ = status.ToString();
			return -1;
		}
	}

	bool RocksDbDriver::Put(const std::string &key, const std::string &value) {
		assert(db_ != NULL);
		rocksdb::WriteOptions opt;
		opt.sync = true;
		rocksdb::Status status = db_->Put(opt, key, value);
		if (!status.ok()) {
			utils::MutexGuard guard(mutex_);
			error_desc_ = status.ToString();
		}
		return status.ok();
	}

	bool RocksDbDriver::Delete(const std::string &key) {
		assert(db_ != NULL);
		rocksdb::WriteOptions opt;
		opt.sync = true;
		rocksdb::Status status = db_->Delete(opt, key);
		if (!status.ok()) {
			utils::MutexGuard guard(mutex_);
			error_desc_ = status.ToString();
		}
		return status.ok();
	}

	bool RocksDbDriver::WriteBatch(WRITE_BATCH &write_batch) {

		rocksdb::WriteOptions opt;
		opt.sync = true;
		rocksdb::Status status = db_->Write(opt, &write_batch);
		if (!status.ok()) {
			utils::MutexGuard guard(mutex_);
			error_desc_ = status.ToString();
		}
		return status.ok();
	}

	void* RocksDbDriver::NewIterator() {
		return db_->NewIterator(rocksdb::ReadOptions());
	}

	bool RocksDbDriver::GetOptions(Json::Value &options) {
		std::string out;
		db_->GetProperty("rocksdb.estimate-table-readers-mem", &out);
		options["rocksdb.estimate-table-readers-mem"] = out;

		db_->GetProperty("rocksdb.cur-size-all-mem-tables", &out);
		options["rocksdb.cur-size-all-mem-tables"] = out;

		db_->GetProperty("rocksdb.stats", &out);
		options["rocksdb.stats"] = out;
		return true;
	}
#endif

	Storage::Storage() {
		keyvalue_db_ = NULL;
		ledger_db_ = NULL;
		account_db_ = NULL;
		check_interval_ = utils::MICRO_UNITS_PER_SEC;
	}

	Storage::~Storage() {}

	bool Storage::Initialize(const DbConfigure &db_config, bool bdropdb) {
	
		do {
			std::string strConnect = "";
			std::string str_dbname = "";
			std::vector<std::string> nparas = utils::String::split(db_config.rational_string_, " ");
			for (std::size_t i = 0; i < nparas.size(); i++) {
				std::string str = nparas[i];
				std::vector<std::string> n = utils::String::split(str, "=");
				if (n.size() == 2) {
					if (n[0] != "dbname") {
						strConnect += " ";
						strConnect += str;
					}
					else {
						str_dbname = n[1];
					}
				}
			}

			if (bdropdb) {
				bool do_success = false;
				do {
					if (utils::File::IsExist(db_config.keyvalue_db_path_) && !utils::File::DeleteFolder(db_config.keyvalue_db_path_)) {
						LOG_ERROR_ERRNO("Delete keyvalue db failed", STD_ERR_CODE, STD_ERR_DESC);
					}

					if (utils::File::IsExist(db_config.ledger_db_path_) && !utils::File::DeleteFolder(db_config.ledger_db_path_)) {
						LOG_ERROR_ERRNO("Delete ledger db failed", STD_ERR_CODE, STD_ERR_DESC);
					}
					
					if (utils::File::IsExist(db_config.account_db_path_) && !utils::File::DeleteFolder(db_config.account_db_path_)) {
						LOG_ERROR_ERRNO("Delete account db failed", STD_ERR_CODE, STD_ERR_DESC);
					}
					
					LOG_INFO("Drop db successful");
					do_success = true;
				} while (false);

				return do_success;
			}

			keyvalue_db_ = NewKeyValueDb(db_config);
			if (!keyvalue_db_->Open(db_config.keyvalue_db_path_)) {
				LOG_ERROR("Keyvalue_db path(%s) open fail(%s)\n",
					db_config.keyvalue_db_path_.c_str(), keyvalue_db_->error_desc().c_str());
				break;
			}

			ledger_db_ = NewKeyValueDb(db_config);
			if (!ledger_db_->Open(db_config.ledger_db_path_)) {
				LOG_ERROR("Ledger db path(%s) open fail(%s)\n",
					db_config.ledger_db_path_.c_str(), ledger_db_->error_desc().c_str());
				break;
			}

			account_db_ = NewKeyValueDb(db_config);
			if (!account_db_->Open(db_config.account_db_path_)) {
				LOG_ERROR("Ledger db path(%s) open fail(%s)\n",
					db_config.account_db_path_.c_str(), account_db_->error_desc().c_str());
				break;
			}

			TimerNotify::RegisterModule(this);
			return true;

		} while (false);

		CloseDb();
		return false;
	}


	bool  Storage::CloseDb() {
		bool ret1 = true, ret2 = true, ret3 = true;
		if (keyvalue_db_ != NULL) {
			ret1 = keyvalue_db_->Close();
			delete keyvalue_db_;
			keyvalue_db_ = NULL;
		}

		if (ledger_db_ != NULL) {
			ret2 = ledger_db_->Close();
			delete ledger_db_;
			ledger_db_ = NULL;
		}

		if (account_db_ != NULL) {
			ret3 = account_db_->Close();
			delete account_db_;
			account_db_ = NULL;
		}

		return ret1 && ret2 && ret3;
	}

	bool Storage::Exit() {
		return CloseDb();
	}

	void Storage::OnSlowTimer(int64_t current_time) {
	}

	KeyValueDb *Storage::keyvalue_db() {
		return keyvalue_db_;
	}

	KeyValueDb *Storage::ledger_db() {
		return ledger_db_;
	}

	KeyValueDb *Storage::account_db() {
		return account_db_;
	}

	KeyValueDb *Storage::NewKeyValueDb(const DbConfigure &db_config) {
		KeyValueDb *db = NULL;
#ifdef WIN32
		db = new LevelDbDriver();
#else
		db = new RocksDbDriver();
#endif

		return db;
	}
}