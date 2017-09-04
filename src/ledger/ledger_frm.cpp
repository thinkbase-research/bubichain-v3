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

#include <sstream>

#include <utils/utils.h>
#include <common/storage.h>
#include <common/pb2json.h>
#include <glue/glue_manager.h>
#include "ledger_manager.h"
#include "ledger_frm.h"

namespace bubi {
#define COUNT_PER_PARTITION 1000000
	LedgerFrm::LedgerFrm() {
		id_ = 0;
	}

	
	LedgerFrm::~LedgerFrm() {
	}


	//bool LedgerFrm::LoadFromDb(int64_t ledger_seq, protocol::Ledger &ledger) {
	//	return true;
	//}

	bool LedgerFrm::LoadFromDb(int64_t ledger_seq) {

		bubi::KeyValueDb *db = bubi::Storage::Instance().ledger_db();
		std::string ledger_header;
		db->Get(ComposePrefix(General::LEDGER_PREFIX, ledger_seq), ledger_header);
		ledger_.mutable_header()->ParseFromString(ledger_header);

		return true;
	}


	bool LedgerFrm::AddToDb(WRITE_BATCH &batch) {
		KeyValueDb *db = Storage::Instance().ledger_db();

		batch.Put(bubi::General::KEY_LEDGER_SEQ, utils::String::ToString(ledger_.header().seq()));
		batch.Put(ComposePrefix(General::LEDGER_PREFIX, ledger_.header().seq()), ledger_.header().SerializeAsString());
		
		protocol::EntryList list;
		for (size_t i = 0; i < apply_tx_frms_.size(); i++) {
			const TransactionFrm::pointer ptr = apply_tx_frms_[i];

			protocol::TransactionEnvStore env_store;
			*env_store.mutable_transaction_env() = apply_tx_frms_[i]->GetTransactionEnv();
			env_store.set_ledger_seq(ledger_.header().seq());
			env_store.set_close_time(ledger_.header().close_time());
			env_store.set_error_code(ptr->GetResult().code());
			env_store.set_error_desc(ptr->GetResult().desc());

			batch.Put(ComposePrefix(General::TRANSACTION_PREFIX, ptr->GetContentHash()), env_store.SerializeAsString());
			list.add_entry(ptr->GetContentHash());

			for (size_t j = 0; j < ptr->instructions_.size(); j++){
				protocol::TransactionEnvStore env_sto = ptr->instructions_.at(j);
				env_sto.set_ledger_seq(ledger_.header().seq());
				env_sto.set_close_time(ledger_.header().close_time());
				std::string hash = HashWrapper::Crypto(env_sto.transaction_env().transaction().SerializeAsString());
				batch.Put(ComposePrefix(General::TRANSACTION_PREFIX, hash), env_sto.SerializeAsString());
				list.add_entry(hash);
			}
		}

		batch.Put(ComposePrefix(General::LEDGER_TRANSACTION_PREFIX, ledger_.header().seq()), list.SerializeAsString());

		//save the last tx hash, temporary
		if (list.entry_size() > 0) {
			protocol::EntryList new_last_hashs;
			if (list.entry_size() < General::LAST_TX_HASHS_LIMIT) {
				std::string str_last_hashs;
				int32_t ncount = db->Get(General::LAST_TX_HASHS, str_last_hashs);
				if (ncount < 0) {
					LOG_ERROR("Load last tx hash failed, error desc(%s)", db->error_desc().c_str());
				}

				protocol::EntryList exist_hashs;
				if (ncount > 0 && !exist_hashs.ParseFromString(str_last_hashs)) {
					LOG_ERROR("Parse from string failed");
				}

				for (int32_t i = list.entry_size() - 1; i >= 0; i--) {
					*new_last_hashs.add_entry() = list.entry(i);
				}

				for (int32_t i = 0; 
					i < exist_hashs.entry_size() && new_last_hashs.entry_size() < General::LAST_TX_HASHS_LIMIT;
					i++) { 
					*new_last_hashs.add_entry() = exist_hashs.entry(i);
				}
			} else{
				for (int32_t i = list.entry_size() - 1; i >= list.entry_size() - General::LAST_TX_HASHS_LIMIT; i--) {
					*new_last_hashs.add_entry() = list.entry(i);
				}
			}

			batch.Put(General::LAST_TX_HASHS, new_last_hashs.SerializeAsString());
		}

		if (!db->WriteBatch(batch)){
			BUBI_EXIT("Write ledger and transaction failed(%s)", db->error_desc().c_str());
		}
		return true;
	}

	bool LedgerFrm::Apply(const protocol::ConsensusValue& request)
	{
		value_ = std::make_shared<protocol::ConsensusValue>(request);
		uint32_t success_count = 0;
		environment_ = std::make_shared<Environment>(nullptr);

		for (int i = 0; i < request.txset().txs_size(); i++) {
			auto txproto = request.txset().txs(i);
			
			TransactionFrm::pointer tx_frm = std::make_shared<TransactionFrm>(txproto, environment_);
			LedgerManager::Instance().transaction_stack_.push(tx_frm);

			if (!tx_frm->ValidForApply()){
				continue;
			}

			if (!tx_frm->Apply(this)){
				LOG_ERROR("transaction(%s) apply failed. %s",
					utils::String::BinToHexString(tx_frm->GetContentHash()).c_str(), tx_frm->GetResult().desc().c_str());
			}
			else{
				tx_frm->environment_->Commit();
			}
			apply_tx_frms_.push_back(tx_frm);
			ledger_.add_transaction_envs()->CopyFrom(txproto);
			LedgerManager::Instance().transaction_stack_.pop();
		}

		return true;
	}

	bool LedgerFrm::CheckValidation() {
		return true;
	}

	Json::Value LedgerFrm::ToJson() {
		return bubi::Proto2Json(ledger_);
	}

	protocol::Ledger &LedgerFrm::ProtoLedger() {
		return ledger_;
	}

	bool LedgerFrm::Commit(KVTrie* trie) {
		auto batch = trie->batch_;
		for (auto it = environment_->entries_.begin(); it != environment_->entries_.end(); it++){
			std::shared_ptr<AccountFrm> account = it->second;
			account->UpdateHash(batch);
			std::string ss = account->Serializer();
			std::string index = utils::String::HexStringToBin(it->first);
			trie->Set(index, ss);
		}
	/*	for (auto it = environment_->entries_.begin(); it != environment_->entries_.end(); it++) {
			auto &r = it->second;
			switch (r.action_) {
			case utils::ChangeAction::DEL:{
				break;
			}
			case utils::ChangeAction::ADD:
			case utils::ChangeAction::MOD:
			case utils::ChangeAction::KEEP:{
				std::shared_ptr<AccountFrm> account = it->second.value_;
				account->UpdateHash(batch);
				std::string ss = account->Serializer();
				std::string index = utils::String::HexStringToBin(it->first);
				trie->Set(index, ss);
				break;
			}
			default:
				break;
			}
		}*/
		return true;
	}
}
