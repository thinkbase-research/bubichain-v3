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

#ifndef PBFT_H_
#define PBFT_H_

#include "consensus.h"
#include "pbft_instance.h"

namespace bubi {

	class Pbft : public Consensus {
		friend class PbftInstance;
		friend class PbftVcInstance;
	private:
		//for pbft instance
		PbftInstanceMap instances_;
		int64_t view_number_;
		int64_t sequence_;

		int64_t ckp_count_; //checkpoint number, such as 5
		int64_t ckp_interval_;
		int64_t last_exe_seq_;

		int64_t low_water_mark_;

		size_t fault_number_;

		//for checkpoint
		PbftCkpInstanceMap ckp_instances_;
		bool view_active_;

		//for view change 
		PbftVcInstanceMap vc_instances_;

		//for synchronize
		PbftInstanceMap out_pbft_instances_;

		//check interval
		int64_t last_check_time_;

		//for change view timer
		int64_t new_view_repond_timer_;

		PbftEnvPointer NewPrePrepare(const std::string &value);
		protocol::PbftEnv NewPrePrepare(const protocol::PbftPrePrepare &pre_prepare);
		PbftEnvPointer NewPrepare(const protocol::PbftPrePrepare &pre_prepare, int64_t round_number);
		PbftEnvPointer NewCommit(const protocol::PbftPrepare &prepare, int64_t round_number);
		PbftEnvPointer NewCheckPoint(const std::string &state_digest, int64_t seq);
		PbftEnvPointer NewViewChange(int64_t view_number);
		PbftEnvPointer NewNewView(PbftVcInstance &vc_instance, std::map<int64_t, protocol::PbftEnv> &pre_prepares, int64_t sequence);
		bool OnPrePrepare(const protocol::Pbft &pre_prepare, PbftInstance &pinstance, int32_t check_value_ret);
		bool OnPrepare(const protocol::Pbft &prepare, PbftInstance &pinstance);
		bool OnCommit(const protocol::Pbft &commit, PbftInstance &pinstance);
		bool OnCheckPoint(const protocol::PbftEnv &pbft);
		bool OnViewChange(const protocol::PbftEnv &pbft);
		bool OnNewView(const protocol::PbftEnv &pbft);

		bool CheckViewChange(const protocol::PbftViewChange &view_change);
		bool CreateViewChangeParam(const PbftVcInstance &vc_instance, std::map<int64_t, protocol::PbftEnv> &pre_prepares, PbftCkpInstancePair &lasted_ckp_pair);
		bool ProcessQuorumViewChange(PbftVcInstance &vc_instance);

		PbftInstance *CreateInstanceIfNotExist(const protocol::PbftEnv &env);
		bool InWaterMark(int64_t seq);
		bool TryExecuteValue();
		bool TryMoveWaterMark();
		bool CheckMessageItem(const protocol::PbftEnv &env);
		static bool CheckMessageItem(const protocol::PbftEnv &env, const ValidatorMap &validators);
		bool TraceOutPbftCommit(const protocol::PbftEnv &env);
		bool TraceOutPbftPrePrepare(const protocol::PbftEnv &env);
		void TryDoTraceOut(const PbftInstanceIndex &index, const PbftInstance &instance);
		static size_t GetQuorumSize(size_t size);
		void ClearNotCommitedInstance();

		void LoadValues();
		int32_t LoadCheckPoint();
		bool SaveCheckPoint(ValueSaver &saver);
		int32_t LoadInstance();
		bool SaveInstance(ValueSaver &saver);
		int32_t LoadVcInstance();
		int32_t LoadValidators();
		bool SaveValidators(ValueSaver &saver);
		bool SaveViewChange(ValueSaver &saver);
		bool SendMessage(const PbftEnvPointer &msg);
	public:
		Pbft();
		~Pbft();

		PbftEnvPointer IncPeerMessageRound(const protocol::PbftEnv &message, uint32_t round_number);

		virtual bool Initialize();
		virtual bool Exit();
		virtual bool Request(const std::string &value);
		virtual bool RepairStatus(); // true : it is normal, false : waiting for pbft's notify
		virtual bool OnRecv(const ConsensusMsg &meesage);

		virtual void OnTimer(int64_t current_time);
		virtual void OnSlowTimer(int64_t current_time) {};
		virtual void OnTxTimeout();
		virtual size_t GetQuorumSize();
		virtual void GetModuleStatus(Json::Value &data);
		virtual int32_t IsLeader();
		virtual bool CheckProof(const protocol::ValidatorSet &validators, const std::string &previous_value_hash, const std::string &proof);
		virtual bool UpdateValidators(const protocol::ValidatorSet &validators, const std::string &proof);

		static int64_t GetSeq(const protocol::PbftEnv &pbft_env);
		static std::string GetNodeAddress(const protocol::PbftEnv &pbft_env);
		static std::vector<std::string> GetValue(const protocol::PbftEnv &pbft_env);
		static const char *GetPhaseDesc(PbftInstancePhase phase);
		static void ClearStatus();

	};

}

#endif
