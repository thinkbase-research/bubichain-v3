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

#ifndef TRANSACTION_FRM_H_
#define TRANSACTION_FRM_H_

#include <unordered_map>
#include <utils/common.h>
#include <common/general.h>
#include <ledger/account.h>
#include <overlay/peer.h>
#include <api/web_server.h>
#include <proto/cpp/overlay.pb.h>
#include "operation_frm.h"
#include "environment.h"

namespace bubi {

	class OperationFrm;
	class AccountEntry;
	class LedgerFrm;
	class TransactionFrm {
	public:
		typedef std::shared_ptr<bubi::TransactionFrm> pointer;

		std::set<std::string> involved_accounts_;
		std::vector<protocol::TransactionEnvStore> instructions_;
		std::shared_ptr<Environment> environment_;
	public:
		//only valid when the transaction belongs to a txset
		TransactionFrm();
		TransactionFrm(const protocol::TransactionEnv &env, std::shared_ptr<Environment> environment = nullptr);
		
		virtual ~TransactionFrm();
		
		static bool AccountFromDB(const std::string &address, AccountFrm::pointer &account_ptr);

		std::string GetContentHash() const;
		std::string GetContentData() const;
		std::string GetFullHash() const;

		void ToJson(Json::Value &json);

		std::string GetSourceAddress() const;
		int64_t GetNonce() const;

		const protocol::TransactionEnv &GetTransactionEnv() const;

		bool CheckValid(int64_t last_seq);

		bool SignerHashPriv(utils::StringVector &address, std::shared_ptr<Environment> env, int32_t type) const;

		const protocol::Transaction &GetTx() const;

		Result GetResult() const;

		void Initialize();

		uint32_t LoadFromDb(const std::string &hash);

		bool CheckTimeout(int64_t expire_time);

		bool Apply(LedgerFrm* ledger_frm, bool bool_contract = false);

		protocol::TransactionEnv &GetProtoTxEnv() {
			return transaction_env_;
		}

		bool ValidForParameter();
		
		bool ValidForSourceSignature();

		bool ValidForApply();

		uint64_t apply_time_;
		Result result_;	
		int32_t processing_operation_;
		LedgerFrm* ledger_;
	private:		
		protocol::TransactionEnv transaction_env_;
		std::string hash_;
		std::string full_hash_;
		std::string data_;
		std::string full_data_;
		std::set<std::string> valid_signature_;
		
		int64_t incoming_time_;
	};
};

#endif