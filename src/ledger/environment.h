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

#ifndef ENVIRONMENT_H_
#define ENVIRONMENT_H_

#include <proto/cpp/chain.pb.h>
#include <utils/entry_cache.h>
#include "account.h"

namespace bubi {

	class Environment :public utils::EntryCache<std::string, AccountFrm, StringSort> {

		virtual bool LoadValue(const std::string &address, AccountFrm::pointer &frm) {
			AccountFrm::pointer account_pt;
			if (!Environment::AccountFromDB(address, account_pt)) {
				return false;
			}
			else
				frm = account_pt;
			return true;
		}

	public:

		Environment() {
			parent_ = nullptr;
		}

		Environment(std::shared_ptr<Environment> p) {
			parent_ = p;
		}

		~Environment(){
		}

		void Commit(){
			if (parent_ == nullptr){
				return;
			}
			for (auto it = entries_.begin(); it != entries_.end(); it++) {
				std::shared_ptr<AccountFrm> account = it->second.value_;
				parent_->entries_[it->first] = it->second;
			}
		}

		static bool AccountFromDB(const std::string &address, AccountFrm::pointer &account_ptr);
		static int64_t time_;
	};
}
#endif