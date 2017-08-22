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

#include <common/storage.h>
#include "ledger_manager.h"

namespace bubi{

	int64_t Environment::time_ = 0;

	bool Environment::AccountFromDB(const std::string &address, AccountFrm::pointer &account_ptr){
		int64_t t1 = utils::Timestamp::HighResolution();
		auto db = Storage::Instance().account_db();
		std::string index = utils::String::HexStringToBin(address);
		std::string buff;
		if (!LedgerManager::Instance().tree_->Get(index, buff)){
			int64_t t2 = utils::Timestamp::HighResolution();
			time_ += (t2 - t1);
			return false;
		}
		int64_t t2 = utils::Timestamp::HighResolution();
		time_ += (t2 - t1);
		protocol::Account account;
		if (!account.ParseFromString(buff)){
			BUBI_EXIT("fatal error, account(%s) ParseFromString failed", address.c_str());
		}
		account_ptr = std::make_shared<AccountFrm>(account);
		return true;
	}
}