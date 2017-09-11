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

#include <utils/logger.h>
#include <utils/timestamp.h>
#include <common/general.h>
#include <common/storage.h>
#include <common/private_key.h>
#include <common/ca_manager.h>
#include <glue/glue_manager.h>
#include <proto/cpp/overlay.pb.h>
#include <ledger/ledger_manager.h>
#include <main/configure.h>
#include <ledger/transaction_frm.h>
#include "peer_manager.h"

namespace bubi {

	void PeerManager::Run(utils::Thread *thread) {
		const P2pNetwork &p2p_configure = Configure::Instance().p2p_configure_.consensus_network_configure_;
		utils::InetAddress listen_address_ = utils::InetAddress::Any();
		listen_address_.SetPort(p2p_configure.listen_port_);
		consensus_network_->Start(listen_address_);
	}

	PeerManager::PeerManager()
		:consensus_network_(NULL),
		thread_ptr_(NULL),
		priv_key_(SIGNTYPE_CFCASM2),
		cert_enabled_(false) {}

	PeerManager::~PeerManager() {
		if (thread_ptr_) {
			delete thread_ptr_;
		}
		if (consensus_network_) {
			delete consensus_network_;
		}
	}

	bool PeerManager::Initialize(char *serial_num, bool cert_enabled) {
		cert_enabled_ = cert_enabled;

		if (serial_num != NULL) {
			serial_num_ = serial_num;
		}
		if (!priv_key_.From(Configure::Instance().p2p_configure_.node_private_key_)) {
			LOG_ERROR("Initialize node private key failed");
			return false;
		}
		peer_node_address_ = priv_key_.GetBase16Address();

		SslParameter ssl_parameter;
		const SSLConfigure& ssl_configure = Configure::Instance().p2p_configure_.ssl_configure_;
		std::string strHome = utils::File::GetBinHome();
		ssl_parameter.cert_password_ = ssl_configure.private_password_;
		ssl_parameter.chain_file_ = utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.chain_file_.c_str());
		ssl_parameter.private_key_file_ = utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.private_key_file_.c_str());
		ssl_parameter.tmp_dh_file_ = utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.dhparam_file_.c_str());
		ssl_parameter.verify_file_ = utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.verify_file_.c_str());
		ssl_parameter.enable_ = cert_enabled;

		consensus_network_ = new PeerNetwork(ssl_parameter);
		if (!consensus_network_->Initialize(peer_node_address_)) {
			return false;
		}

		thread_ptr_ = new utils::Thread(this);
		if (!thread_ptr_->Start("peer-manager")) {
			return false;
		}
		StatusModule::RegisterModule(this);
		TimerNotify::RegisterModule(this);

		return true;
	}

	bool PeerManager::Exit() {
		bool ret1 = false;
		bool ret2 = false;
		if (consensus_network_) {
			consensus_network_->Stop();
		}
		if (thread_ptr_) {
			ret1 = thread_ptr_->JoinWithStop();
		}
		if (consensus_network_) {
			ret2 = consensus_network_->Exit();
		}
		return ret1 && ret2;
	}


	void PeerManager::Broadcast(int64_t type, const std::string &data) {
		if (consensus_network_) consensus_network_->BroadcastMsg(type, data);
	}


	bool PeerManager::SendRequest(int64_t peer_id, int64_t type, const std::string &data) {
		if (consensus_network_) consensus_network_->SendRequest(peer_id, type, data);
		return true;
	}

	void PeerManager::GetModuleStatus(Json::Value &data) {
		data["name"] = "peer_manager";
		data["peer_node_address"] = peer_node_address_;
		if (consensus_network_) consensus_network_->GetModuleStatus(data["consensus_network"]);
	}

	void PeerManager::OnSlowTimer(int64_t current_time) {
		if (!cert_enabled_) {
			return;
		}
	}
}