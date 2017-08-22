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

#include <overlay/peer_manager.h>
#include <ledger/ledger_manager.h>
#include "glue_manager.h"
#include "ledger_upgrade.h"

namespace bubi {
	LedgerUpgradeFrm::LedgerUpgradeFrm() {}
	LedgerUpgradeFrm::~LedgerUpgradeFrm() {}
	bool LedgerUpgradeFrm::operator < (const LedgerUpgradeFrm &frm) const {
		std::string str1 = msg.upgrade().SerializeAsString();
		std::string str2 = frm.msg.upgrade().SerializeAsString();
		return str1.compare(str2) < 0;
	}

	void LedgerUpgradeFrm::ToJson(Json::Value &value) const {
		value["recv_time"] = recv_time;
		value["address"] = address;
		value["msg"] = Proto2Json(msg);
	}

	LedgerUpgrade::LedgerUpgrade() :
		last_send_time_(0){}
	LedgerUpgrade::~LedgerUpgrade() {}

	void LedgerUpgrade::OnTimer(int64_t current_time) {

		do {
			utils::MutexGuard guard(lock_);

			//delete the expire
			for (LedgerUpgradeFrmMap::iterator iter = current_states_.begin();
				iter != current_states_.end();
				) {
				const LedgerUpgradeFrm &frm = iter->second;
				if (frm.recv_time + 300 * utils::MICRO_UNITS_PER_SEC < current_time) {
					current_states_.erase(iter++);
				}
				else {
					iter++;
				}
			}

		} while (false);

		//send the current state every 30s'
		protocol::LedgerUpgradeNotify *notify = NULL;
		do {
			utils::MutexGuard guard(lock_);
			if (current_time - last_send_time_ > 30 * utils::MICRO_UNITS_PER_SEC &&
				(local_state_.add_validators_size() > 0 ||
				local_state_.del_validators_size() > 0 ||
				local_state_.new_ledger_version() > 0)) {
				
				notify = new protocol::LedgerUpgradeNotify;
				notify->set_nonce(current_time);
				*notify->mutable_upgrade() = local_state_;

				std::string raw_data = notify->upgrade().SerializeAsString();
				raw_data += utils::String::ToString(current_time);
				*notify->mutable_signature() = GlueManager::Instance().SignConsensusData(raw_data);

				last_send_time_ = current_time;
			}
		} while (false);

		if (notify){
			PeerManager::Instance().Broadcast(protocol::OVERLAY_MSGTYPE_LEDGER_UPGRADE_NOTIFY, notify->SerializeAsString());
			Recv(*notify);
			delete notify;
		}
	}

	void LedgerUpgrade::Recv(const protocol::LedgerUpgradeNotify &msg) {
		const protocol::LedgerUpgrade &upgrade = msg.upgrade();
		const protocol::Signature &sig = msg.signature();
		std::string raw_data = upgrade.SerializeAsString();
		raw_data += utils::String::ToString(msg.nonce());

		if (!PublicKey::Verify(raw_data, sig.sign_data(), sig.public_key())) {
			LOG_ERROR("Verify ledger upgrade failed");
			return;
		} 

		PublicKey pub(sig.public_key());
		LedgerUpgradeFrm frm;
		frm.address = pub.GetBase16Address();
		frm.recv_time = utils::Timestamp::HighResolution();
		frm.msg = msg;

		utils::MutexGuard guard(lock_);
		current_states_[frm.address] = frm;
	}

	bool LedgerUpgrade::GetValid(const protocol::ValidatorSet &validators, size_t quorum_size, protocol::LedgerUpgrade &proto_upgrade) {
		utils::MutexGuard guard(lock_);
		
		if (current_states_.size() == 0) {
			return false;
		} 

		std::set<std::string> validator_set;
		for (int32_t i = 0; i < validators.validators_size(); i++) {
			validator_set.insert(validators.validators(i));
		}

		std::map<LedgerUpgradeFrm, size_t> counter_upgrade;
		for (LedgerUpgradeFrmMap::iterator iter = current_states_.begin();
			iter != current_states_.end();
			iter++
			) {
			const LedgerUpgradeFrm &frm = iter->second;
			if (counter_upgrade.find(frm) == counter_upgrade.end()) {
				counter_upgrade[frm] = 0;
			}

			if (validator_set.find(frm.address) != validator_set.end()) {
				counter_upgrade[frm] = counter_upgrade[frm] + 1;
			}
		}

		for (std::map<LedgerUpgradeFrm, size_t>::iterator iter = counter_upgrade.begin();
			iter != counter_upgrade.end();
			iter++) {
			if (iter->second >= quorum_size){
				const LedgerUpgradeFrm &frm = iter->first;
				proto_upgrade = frm.msg.upgrade();
				return true;
			} 
		}

		return false;
	}

	Result LedgerUpgrade::ConfValidator(const std::string &add, const std::string &del) {
	
		Result result;
		std::vector<std::string> add_validator;
		std::vector<std::string> del_validator;
		add_validator = utils::String::split(add, ",");
		del_validator = utils::String::split(del, ","); 

		protocol::LedgerHeader lcl = LedgerManager::Instance().GetLastClosedLedger();
		protocol::ValidatorSet set;
		if (!LedgerManager::Instance().GetValidators(lcl.seq(), set)) {
			result.set_desc(utils::String::Format("Check valid failed, get validator failed of ledger seq(" FMT_I64 ")",
				lcl.seq()));
			result.set_code(protocol::ERRCODE_INTERNAL_ERROR);
			LOG_ERROR("%s", result.desc().c_str());
			return result;
		}

		//check the add validator exist
		std::set<std::string> duplicate_set;
		std::set<std::string> current_validator;
		for (int32_t i = 0; i < set.validators_size(); i++) current_validator.insert(set.validators(i));
		if (!add.empty()){
			for (size_t i = 0; i < add_validator.size(); i++) {
				std::string item = add_validator[i];
				if (!PublicKey::IsAddressValid(item)) {
					result.set_desc(utils::String::Format("Check command failed, the address(%s) not valid", item.c_str()));
					result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					LOG_ERROR("%s", result.desc().c_str());
					return result;
				}

				if (current_validator.find(item) != current_validator.end()) {
					result.set_desc(utils::String::Format("Check command failed, the address(%s) exist in current validators", item.c_str()));
					result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					LOG_ERROR("%s", result.desc().c_str());
					return result;
				}

				if (duplicate_set.find(item) != duplicate_set.end()) {
					result.set_desc(utils::String::Format("Check command failed, the address(%s) duplicated in upgrade object", item.c_str()));
					result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					LOG_ERROR("%s", result.desc().c_str());
					return result;
				}
				duplicate_set.insert(item);
			}
		}

		//check the del validator set
		if (!del.empty()){
			for (size_t i = 0; i < del_validator.size(); i++) {
				std::string item = del_validator[i];
				if (!PublicKey::IsAddressValid(item)) {
					result.set_desc(utils::String::Format("Check command failed, the address(%s) not valid", item.c_str()));
					result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					LOG_ERROR("%s", result.desc().c_str());
					return result;
				}

				if (current_validator.find(item) == current_validator.end()) {
					result.set_desc(utils::String::Format("Check command failed, the del address (%s) not exist in current validators", item.c_str()));
					result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					LOG_ERROR("%s", result.desc().c_str());
					return result;
				}

				if (duplicate_set.find(item) != duplicate_set.end()) {
					result.set_desc(utils::String::Format("Check command failed, the del address(%s) duplicated in upgrade object", item.c_str()));
					result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					LOG_ERROR("%s", result.desc().c_str());
					return result;
				}
				duplicate_set.insert(item);
			}
		} 

		utils::MutexGuard guard(lock_);

		local_state_.clear_add_validators();
		local_state_.clear_del_validators();
		if (!add.empty()) {
			for (size_t i = 0; i < add_validator.size(); i++) {
				local_state_.add_add_validators(add_validator[i]);
			}
		}

		if (!del.empty()) {
			for (size_t i = 0; i < del_validator.size(); i++) {
				local_state_.add_del_validators(del_validator[i]);
			}
		}

		LOG_INFO("Prepare config validator, add(%s), del(%s)", add.c_str(), del.c_str());
		return result;
	}

	bool LedgerUpgrade::ConfNewVersion(int32_t new_version) {
		local_state_.set_new_ledger_version(new_version);
		LOG_INFO("Prepare config new version(%d)", new_version);
		return true;
	}

	protocol::LedgerUpgrade LedgerUpgrade::GetLocalState() {
		utils::MutexGuard guard(lock_);
		return local_state_;
	}

	void LedgerUpgrade::LedgerHasUpgrade() {
		utils::MutexGuard guard(lock_);
		local_state_.Clear();
		current_states_.clear();
	}

	void LedgerUpgrade::GetModuleStatus(Json::Value &value) {
		utils::MutexGuard guard(lock_);
		value["local_state"] = Proto2Json(local_state_);
		Json::Value &current_states = value["current_states"];
		for (LedgerUpgradeFrmMap::iterator iter = current_states_.begin();
			iter != current_states_.end();
			iter++) {
			iter->second.ToJson(current_states[current_states.size()]);
		}
	}
}
