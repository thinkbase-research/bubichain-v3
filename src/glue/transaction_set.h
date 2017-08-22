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

#ifndef TRANSACTION_SET_
#define TRANSACTION_SET_

#include <proto/cpp/overlay.pb.h>
#include <proto/cpp/chain.pb.h>
#include <ledger/transaction_frm.h>

namespace bubi {

	//transaction lite set frame
	class TransactionSetFrm {
		protocol::TransactionEnvSet raw_txs_;
		std::map<std::string, int64_t> topic_seqs_;
	public:
		TransactionSetFrm();
		TransactionSetFrm(const protocol::TransactionEnvSet &env);
		~TransactionSetFrm();
		int32_t Add(const TransactionFrm::pointer &tx);
		std::string GetSerializeString() const;
		int32_t Size() const;
		const protocol::TransactionEnvSet &GetRaw() const;
		bool CheckValid() const;
	};
	typedef std::map<int64_t, TransactionFrm::pointer> TransactionFrmMap;

	//topic key
	class TopicKey {
		std::string topic_;
		int64_t sequence_;
	public:
		TopicKey();
		TopicKey(const std::string &topic, int64_t sequence);
		~TopicKey();

		const std::string &GetTopic() const;
		const int64_t GetSeq() const;

		bool operator<(const TopicKey &key) const;
	};

	typedef std::map<TopicKey, TransactionFrm::pointer> TransactionMap;
}

#endif
