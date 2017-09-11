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

#ifndef CONSENSUS_H_
#define CONSENSUS_H_

#include <utils/common.h>
#include <common/general.h>
#include <common/private_key.h>
#include <common/storage.h>
#include <proto/cpp/consensus.pb.h>
#include "consensus_msg.h"

namespace bubi {
	class IConsensusNotify {
	public:
		IConsensusNotify() {};
		~IConsensusNotify() {};

		virtual std::string OnValueCommited(int64_t request_seq, const std::string &value, const std::string &proof, bool calculate_total) = 0;
		virtual void OnViewChanged() = 0;
		virtual int32_t CheckValue(const std::string &value) = 0;
		virtual void SendConsensusMessage(const std::string &message) = 0;
		virtual std::string FetchNullMsg() = 0;
		virtual void OnResetCloseTimer() = 0;
		virtual std::string DescConsensusValue(const std::string &request) = 0;
	};

	typedef std::map<std::string, int64_t> ValidatorMap;
	class Consensus {
	protected:
		std::string name_;

		bool is_validator_;
		PrivateKey private_key_;
		int64_t replica_id_;
		std::map<std::string, int64_t> validators_;

		//lock the instance
		utils::Mutex lock_;

		//notify
		IConsensusNotify *notify_;

		int32_t CheckValue(const std::string &value);
		bool SendMessage(const std::string &message);
		std::string OnValueCommited(int64_t request_seq, const std::string &value, const std::string &proof, bool calculate_total);
		void OnViewChanged();
		
		//only called by drived class
		bool UpdateValidators(const protocol::ValidatorSet &validators);
	public:
		Consensus();
		~Consensus();

		enum CheckValueResult {
			CHECK_VALUE_VALID,
			CHECK_VALUE_MAYVALID,
			CHECK_VALUE_INVALID
		};

		virtual bool Initialize();
		virtual bool Exit();
		virtual bool Request(const std::string &value) { return true; };
		virtual bool RepairStatus() { return true; }; // true : it is normal, false : waiting for pbft's notify
		virtual bool OnRecv(const ConsensusMsg &message) { return true; };
		virtual size_t GetQuorumSize() { return 0; };

		virtual void OnTimer(int64_t current_time) {};
		virtual void OnSlowTimer(int64_t current_time) {};
		virtual void GetModuleStatus(Json::Value &data) {};
		virtual void OnTxTimeout() {};
		virtual bool CheckProof(const protocol::ValidatorSet &validators, const std::string &previous_value_hash, const std::string &proof) { return true; };
		virtual bool UpdateValidators(const protocol::ValidatorSet &validators, const std::string &proof) { return true; };

		static int32_t CompareValue(const std::string &value1, const std::string &value2);

		static bool SaveValue(const std::string &name, const std::string &value);
		static bool SaveValue(const std::string &name, int64_t value);
		static int32_t LoadValue(const std::string &name, std::string &value);
		static int32_t LoadValue(const std::string &name, int64_t &value);
		static bool DelValue(const std::string &name);
		void SetNotify(IConsensusNotify *notify);

		bool IsValidator();
		protocol::Signature SignData(const std::string &data);
		virtual int32_t IsLeader() { return -1; };
		std::string GetNodeAddress();
		int64_t GetValidatorIndex(const std::string &node_address) const;
		static int64_t GetValidatorIndex(const std::string &node_address, const ValidatorMap &validators);
		std::string DescRequest(const std::string &value);
		bool GetValidation(protocol::ValidatorSet &validators, size_t &quorum_size);
	};

	class ValueSaver {
	public:
		ValueSaver();
		~ValueSaver();

		size_t write_size;
		WRITE_BATCH writes;

		void SaveValue(const std::string &name, const std::string &value);
		void SaveValue(const std::string &name, int64_t value);
		void DelValue(const std::string &name);
		bool Commit();
	};

	class OneNode : public Consensus {
	public:
		OneNode();
		~OneNode();

		virtual bool Request(const std::string &value);
		virtual void GetModuleStatus(Json::Value &data);
	};

}

#endif
