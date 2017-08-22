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

#ifndef GLUE_MANAGER_
#define GLUE_MANAGER_

#include <utils/singleton.h>
#include <utils/net.h>
#include <utils/lrucache.hpp>
#include <overlay/peer.h>
#include <consensus/consensus_manager.h>
#include "transaction_set.h"
#include "ledger_upgrade.h"

namespace bubi {

	class GlueManager : public utils::Singleton < bubi::GlueManager>,
		public bubi::TimerNotify,
		public bubi::StatusModule,
		public IConsensusNotify {

		friend class TransactionSetFrm;

		std::map<std::string, int64_t> last_topic_seqs_;
		TransactionMap topic_caches_;
		utils::Mutex lock_;

		int64_t time_start_consenus_;
		std::shared_ptr<Consensus> consensus_;

		int64_t ledgerclose_check_timer_;
		int64_t empty_transaction_times_;
		int64_t start_consensus_timer_;

		//for get module status
		time_t process_uptime_;

		//for temp validation storage, need implement by ledger
		//validations
		protocol::ValidatorSet validations;

		//public key

		//for ledger upgrade
		LedgerUpgrade ledger_upgrade_;

		bool LoadLastLedger();
		bool CreateGenesisLedger();
		void StartLedgerCloseTimer();
	public:
		GlueManager();
		~GlueManager();

		bool Initialize();
		bool Exit();

		bool StartConsensus(); //start to trigger consensus
		bool CreateTableIfNotExist(); //create the db
		std::string CalculateTxTreeHash(const std::vector<TransactionFrm::pointer> &tx_array);
		size_t RemoveTxset(const TransactionSetFrm &set);
		//const LedgerHeaderLiteFrmPtr GetLastLedger() const { return last_ledger_; };
		int64_t GetIntervalTime(bool empty_block);

		bool OnTransaction(TransactionFrm::pointer tx, Result &err);
		void OnConsensus(const ConsensusMsg &msg);
		void NotifyErrTx(std::vector<TransactionFrm::pointer> &txs);

		//called by ledger manger once ledger closed
		void UpdateValidators(const protocol::ValidatorSet &validators, const std::string &proof);

		//called by web server
		Result ConfValidator(const std::string &add, const std::string &del);

		//ledger upgrade
		void OnRecvLedgerUpMsg(const protocol::LedgerUpgradeNotify &msg);
		protocol::Signature SignConsensusData(const std::string &data);

		//should be called by ledger manager
		bool CheckValueAndProof( const std::string &consensus_value, const std::string &proof);
		int32_t CheckValueHelper(const protocol::ConsensusValue &consensus_value);

		virtual void OnTimer(int64_t current_time) override;
		virtual void OnSlowTimer(int64_t current_time) override {};
		virtual void GetModuleStatus(Json::Value &data);
		virtual time_t GetProcessUptime();

		// IConsensusNotify
		virtual std::string OnValueCommited(int64_t request_seq, const std::string &value, const std::string &evidence,bool calculate_total);
		virtual void OnViewChanged();
		virtual int32_t CheckValue(const std::string &value);
		virtual void SendConsensusMessage(const std::string &message);
		virtual std::string FetchNullMsg();
		virtual void OnResetCloseTimer();
		virtual std::string DescConsensusValue(const std::string &request);
	};
};

#endif