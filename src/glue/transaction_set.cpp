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

#include "transaction_set.h"

namespace bubi {
	TransactionSetFrm::TransactionSetFrm(const protocol::TransactionEnvSet &env) {
		raw_txs_ = env;
	}

	TransactionSetFrm::TransactionSetFrm() {
	}

	TransactionSetFrm::~TransactionSetFrm() {}
	int32_t TransactionSetFrm::Add(const TransactionFrm::pointer &tx) {
		if (raw_txs_.ByteSize() + tx->GetTransactionEnv().ByteSize() >= General::TXSET_LIMIT_SIZE) {
			LOG_ERROR("Txset byte size(%d) will be exceed than limit(%d), stop added current tx(size:%d)", 
				raw_txs_.ByteSize(), 
				General::TXSET_LIMIT_SIZE,
				tx->GetTransactionEnv().ByteSize());
			return 0;
		} 

		int64_t last_seq = 0;
		do {
			//find this cache
			std::map<std::string, int64_t>::iterator this_iter = topic_seqs_.find(tx->GetSourceAddress());
			if (this_iter != topic_seqs_.end()) {
				last_seq = this_iter->second;
				break;
			}

			//find global cache
			AccountFrm::pointer account;
			if (Environment::AccountFromDB(tx->GetSourceAddress(), account)) {
				last_seq = account->GetAccountNonce();
			}
		} while (false);

		if (tx->GetNonce() > last_seq + 1) {
			LOG_ERROR("The tx seq(" FMT_I64 ") is large than last seq(" FMT_I64 ") + 1", tx->GetNonce(), last_seq);
			return 0;
		}

		if (tx->GetNonce() <= last_seq) {
			LOG_ERROR("The tx seq(" FMT_I64 ") is less or equal of last seq(" FMT_I64 "), remove it", tx->GetNonce(), last_seq);
			return -1;
		}

		topic_seqs_[tx->GetSourceAddress()] = tx->GetNonce();
		*raw_txs_.add_txs() = tx->GetProtoTxEnv();
		return 1;
	}

	bool TransactionSetFrm::CheckValid() const{
		if (raw_txs_.ByteSize() >= General::TXSET_LIMIT_SIZE) {
			LOG_WARN("The txset size(%d) will be exceed the limit(%d), check invalid",
				raw_txs_.ByteSize(), General::TXSET_LIMIT_SIZE);
			return 0;
		}

		std::string last_address;
		int64_t last_seq = -1;
		for (int32_t i = 0; i < raw_txs_.txs_size(); i++) {
			const protocol::TransactionEnv &env = raw_txs_.txs(i);
			TransactionFrm tx(env);
			if (!tx.CheckValid(-1)) {
				LOG_ERROR("Check txset failed");
				return false;
			}

			const std::string &address = env.transaction().source_address();
			int64_t seq = env.transaction().nonce();
			if (last_seq < 0 || address > last_address) {
				last_seq = seq;
				last_address = address;
			} else {
				if ((address == last_address) && seq == last_seq + 1){
					last_seq = seq;
					continue;
				}
				else {
					Json::Value json_raw = Proto2Json(raw_txs_);
					LOG_ERROR("Check txset failed, as not order(%s)", json_raw.toFastString().c_str());
					return false;
				}
			}
		}

		return true;
	}

	std::string TransactionSetFrm::GetSerializeString() const {
		return raw_txs_.SerializeAsString();
	}

	int32_t TransactionSetFrm::Size() const {
		return raw_txs_.txs_size();
	}

	const protocol::TransactionEnvSet &TransactionSetFrm::GetRaw() const {
		return raw_txs_;
	}

	TopicKey::TopicKey() : sequence_(0) {}
	TopicKey::TopicKey(const std::string &topic, int64_t sequence) : topic_(topic), sequence_(sequence) {}
	TopicKey::~TopicKey() {}

	bool TopicKey::operator<(const TopicKey &key) const {
		if (topic_ < key.topic_) {
			return true;
		}
		else if (topic_ == key.topic_ && sequence_ < key.sequence_) {
			return true;
		}

		return false;
	}

	const std::string &TopicKey::GetTopic() const {
		return topic_;
	}

	const int64_t TopicKey::GetSeq() const {
		return sequence_;
	}
}