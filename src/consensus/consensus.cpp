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

#include <utils/crypto.h>
#include <utils/logger.h>
#include <common/storage.h>
#include <main/configure.h>
#include "consensus.h"

namespace bubi {
	Consensus::Consensus() : name_("consensus"),
		is_validator_(false),
		replica_id_(-1),
		private_key_(Configure::Instance().validation_configure_.node_privatekey_) {}

	Consensus::~Consensus() {}

	bool Consensus::Initialize() {
		if (!private_key_.IsValid()) {
			LOG_ERROR("The consensus private key format is error");
			return false;
		}

		return true;

// 		const ValidationConfigure &config = Configure::Instance().validation_configure_;
// 		int64_t counter = 0;
// 		protocol::ValidatorSet proto_validators;
// 		for (auto const &iter : config.validators_) {
// 			proto_validators.add_validator(iter);
// 		}
// 
// 		return UpdateValidators(proto_validators);
	}

	bool Consensus::Exit() {
		return true;
	}

	bool Consensus::UpdateValidators(const protocol::ValidatorSet &validators) {
		validators_.clear();

		is_validator_ = false;
		std::string node_address = private_key_.GetBase16Address();
		int64_t counter = 0;
		for (int32_t i = 0; i < validators.validators_size(); i++) {
			validators_.insert(std::make_pair(validators.validators(i), counter++));
			if (node_address == validators.validators(i)) {
				is_validator_ = true;
			}
		}

		if (is_validator_) {
			std::map<std::string, int64_t>::const_iterator iter = validators_.find(node_address);
			replica_id_ = iter->second;
		}
		else {
			replica_id_ = -1;
		}

		return true;
	}

	bool Consensus::GetValidation(protocol::ValidatorSet &validators, size_t &quorum_size) {
		std::vector<std::string> vec_validators;
		vec_validators.resize(validators_.size());
		for (std::map<std::string, int64_t>::iterator iter = validators_.begin();
			iter != validators_.end();
			iter++) {
			vec_validators[(uint32_t)iter->second] = iter->first;
		}

		for (size_t i = 0; i < vec_validators.size(); i++) {
			validators.add_validators(vec_validators[i]);
		}

		quorum_size = GetQuorumSize();
		return true;
	}

	protocol::Signature Consensus::SignData(const std::string &data) {
		protocol::Signature sig;
		sig.set_sign_data(private_key_.Sign(data));
		sig.set_public_key(private_key_.GetBase16PublicKey());
		return sig;
	}

	bool Consensus::SendMessage(const std::string &message) {
		if (!is_validator_) {
			return false;
		}

		notify_->SendConsensusMessage(message);
		return true;
	}

	int64_t Consensus::GetValidatorIndex(const std::string &node_address) const {
		return GetValidatorIndex(node_address, validators_);
	}

	int64_t Consensus::GetValidatorIndex(const std::string &node_address, const ValidatorMap &validators) {
		std::map<std::string, int64_t>::const_iterator iter = validators.find(node_address);
		if (iter != validators.end()) {
			return iter->second;
		}

		return -1;
	}

	std::string Consensus::DescRequest(const std::string &value) {
		return notify_->DescConsensusValue(value);
	}

	std::string Consensus::OnValueCommited(int64_t request_seq, const std::string &value, const std::string &proof, bool calculate_total) {
		return notify_->OnValueCommited(request_seq, value, proof, calculate_total);
	}

	void Consensus::OnViewChanged() {
		notify_->OnViewChanged();
	}

	int32_t Consensus::CheckValue(const std::string &value) {
		return notify_->CheckValue(value);
	}

	int32_t Consensus::CompareValue(const std::string &value1, const std::string &value2) {
		return value1.compare(value2);
	}

	bool Consensus::IsValidator() {
		return is_validator_;
	}

	std::string Consensus::GetNodeAddress() {
		return private_key_.GetBase16Address();
	}

	bool Consensus::SaveValue(const std::string &name, const std::string &value) {
		KeyValueDb *db = Storage::Instance().keyvalue_db();
		return db->Put(utils::String::Format("%s_%s", bubi::General::CONSENSUS_PREFIX, name.c_str()), value);
	}

	bool Consensus::SaveValue(const std::string &name, int64_t value) {
		LOG_INFO("Set %s to value(" FMT_I64 ") ", name.c_str(), value);
		return SaveValue(name, utils::String::ToString(value));
	}

	int32_t Consensus::LoadValue(const std::string &name, std::string &value) {
		KeyValueDb *db = Storage::Instance().keyvalue_db();
		return db->Get(utils::String::Format("%s_%s", bubi::General::CONSENSUS_PREFIX, name.c_str()), value) ? 1 : 0;
	}

	bool Consensus::DelValue(const std::string &name) {
		KeyValueDb *db = Storage::Instance().keyvalue_db();
		return db->Delete(utils::String::Format("%s_%s", bubi::General::CONSENSUS_PREFIX, name.c_str())) ? 1 : 0;
	}

	int32_t Consensus::LoadValue(const std::string &name, int64_t &value) {
		std::string strvalue;
		int32_t ret = LoadValue(name, strvalue);
		if (ret > 0) value = utils::String::Stoi64(strvalue);
		return ret;
	}

	void Consensus::SetNotify(IConsensusNotify *notify) {
		notify_ = notify;
	}

	OneNode::OneNode() {
		name_ = "one_node";
	}

	OneNode::~OneNode() {}

	bool OneNode::Request(const std::string &value) {
		OnValueCommited(0, value, "", true);
		return true;
	}

	void OneNode::GetModuleStatus(Json::Value &data) {
		data["type"] = name_;
	}

	ValueSaver::ValueSaver() :write_size(0) {};
	ValueSaver::~ValueSaver() {
		Commit();
	};

	void ValueSaver::SaveValue(const std::string &name, const std::string &value) {
		writes.Put(utils::String::Format("%s_%s", bubi::General::CONSENSUS_PREFIX, name.c_str()), value);
		write_size++;
	}

	void ValueSaver::SaveValue(const std::string &name, int64_t value) {
		LOG_INFO("Set %s to value(" FMT_I64 ") ", name.c_str(), value);
		SaveValue(name, utils::String::ToString(value));
	}

	void ValueSaver::DelValue(const std::string &name) {
		writes.Delete(name);
		write_size++;
	}

	bool ValueSaver::Commit() {
		KeyValueDb *db = Storage::Instance().keyvalue_db();
		bool ret = true;
		if (write_size > 0) {
			ret = db->WriteBatch(writes);
			write_size = 0;
		}

		return true;
	}
}