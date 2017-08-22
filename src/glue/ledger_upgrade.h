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

#ifndef LEDGER_UPGRADE_H_
#define LEDGER_UPGRADE_H_

#include <overlay/peer.h>

namespace bubi {
	class LedgerUpgradeFrm {
	public:
		~LedgerUpgradeFrm();
		LedgerUpgradeFrm();

		int64_t recv_time;
		std::string address;
		protocol::LedgerUpgradeNotify msg;
		bool operator < (const LedgerUpgradeFrm &frm) const;
		void ToJson(Json::Value &value) const;
	};

	typedef std::map<std::string, LedgerUpgradeFrm> LedgerUpgradeFrmMap;

	class LedgerUpgrade {
	public:
		LedgerUpgrade();
		~LedgerUpgrade();

		void OnTimer(int64_t current_time);
		void Recv(const protocol::LedgerUpgradeNotify &msg);
		bool GetValid(const protocol::ValidatorSet &validators, size_t quorum_size, protocol::LedgerUpgrade &proto_upgrade);
		Result ConfValidator(const std::string &add, const std::string &del);
		bool ConfNewVersion(int32_t new_version);
		protocol::LedgerUpgrade GetLocalState();
		void LedgerHasUpgrade();
		void GetModuleStatus(Json::Value &value);

		int64_t last_send_time_;
		protocol::LedgerUpgrade local_state_;
		LedgerUpgradeFrmMap current_states_;
		utils::Mutex lock_;
	};
};

#endif