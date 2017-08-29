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

#include <utils/utils.h>
#include <utils/file.h>
#include <utils/strings.h>
#include <utils/logger.h>
#include <common/general.h>
#include "configure.h"

namespace bubi {

	P2pNetwork::P2pNetwork() :
		target_peer_connection_(50),
		connect_timeout_(5),// second
		heartbeat_interval_(1800) {// second
			listen_port_ = General::CONSENSUS_PORT;
	}

	P2pNetwork::~P2pNetwork() {}

	P2pConfigure::P2pConfigure() :
		network_id_(1){}

	P2pConfigure::~P2pConfigure() {}

	bool P2pConfigure::Load(const Json::Value &value) {
		Configure::GetValue(value, "node_private_key", node_private_key_);
		Configure::GetValue(value, "network_id", network_id_);
		
		//ca_server_configure_.Load(value["ca_server"]);
		ssl_configure_.Load(value["ssl"]);
		consensus_network_configure_.Load(value["consensus_network"]);

		if (value.isMember("transaction_network")) {
			transaction_network_configure_.Load(value["transaction_network"]);
		}
		else {
			transaction_network_configure_ = consensus_network_configure_;
			transaction_network_configure_.listen_port_++;
			for (utils::StringList::iterator iter = transaction_network_configure_.known_peer_list_.begin();
				iter != transaction_network_configure_.known_peer_list_.end();
				iter++) {
				utils::InetAddress temp_addr(*iter);
				temp_addr.SetPort(temp_addr.GetPort() + 1);
				*iter = temp_addr.ToIpPort();
			}
		}

		node_private_key_ = utils::Aes::HexDecrypto(node_private_key_, GetDataSecuretKey());
		return true;
	}

	bool P2pNetwork::Load(const Json::Value &value) {
		int32_t temp;
		Configure::GetValue(value, "target_peer_connection", temp);
		target_peer_connection_ = temp;
		Configure::GetValue(value, "known_peers", known_peer_list_);
		Configure::GetValue(value, "connect_timeout", connect_timeout_);
		Configure::GetValue(value, "heartbeat_interval", heartbeat_interval_);
		Configure::GetValue(value, "listen_port", listen_port_);

		connect_timeout_ = connect_timeout_ * utils::MICRO_UNITS_PER_SEC; //micro second
		heartbeat_interval_ = heartbeat_interval_ * utils::MICRO_UNITS_PER_SEC; //micro second
		return true;
	}

	WsServerConfigure::~WsServerConfigure() {}

	bool WsServerConfigure::Load(const Json::Value &value) {
		std::string address;
		Configure::GetValue(value, "listen_address", address);
		listen_address_ = utils::InetAddress(address);
		Configure::GetValue(value, "listen_tx_status", listen_tx_status_);

		return true;
	}

	WsServerConfigure::WsServerConfigure() {
		listen_tx_status_ = false;
	}

	WebServerConfigure::WebServerConfigure() {
		ssl_enable_ = false;
		query_limit_ = 1000;
		multiquery_limit_ = 100;
		remote_authorized_ = false;
		thread_count_ = 0;
	}

	WebServerConfigure::~WebServerConfigure() {}

	bool WebServerConfigure::Load(const Json::Value &value) {
		std::string listen_address_value;
		ConfigureBase::GetValue(value, "listen_addresses", listen_address_value);
		utils::StringVector address_array = utils::String::Strtok(listen_address_value, ',');
		for (size_t i = 0; i < address_array.size(); i++) {
			listen_addresses_.push_back(utils::InetAddress(address_array[i]));
		}
		ConfigureBase::GetValue(value, "index_name", index_name_);
		ConfigureBase::GetValue(value, "directory", directory_);
		ConfigureBase::GetValue(value, "ssl_enable", ssl_enable_);
		ConfigureBase::GetValue(value, "query_limit", query_limit_);
		ConfigureBase::GetValue(value, "multiquery_limit", multiquery_limit_);
		ConfigureBase::GetValue(value, "remote_authorized", remote_authorized_);
		ConfigureBase::GetValue(value, "thread_count", thread_count_);
		
		if (ssl_enable_)
			ssl_configure_.Load(value["ssl"]);
		return true;
	}

	LedgerConfigure::LedgerConfigure() {
		max_trans_per_ledger_ = 10000;
		max_trans_in_memory_ = 100000;
		max_ledger_per_message_ = 5;
		max_apply_ledger_per_round_ = 3;
		test_model_ = false;
	}

	LedgerConfigure::~LedgerConfigure() {}

	bool LedgerConfigure::Load(const Json::Value &value) {
		Configure::GetValue(value, "base_fee", base_fee_);
		Configure::GetValue(value, "base_reserve", base_reserve_);
		Configure::GetValue(value, "hash_type", hash_type_);
		Configure::GetValue(value, "max_trans_per_ledger", max_trans_per_ledger_);
		Configure::GetValue(value, "max_ledger_per_message", max_ledger_per_message_);
		Configure::GetValue(value, "max_apply_ledger_per_round", max_apply_ledger_per_round_);
		Configure::GetValue(value, "max_trans_in_memory", max_trans_in_memory_);
		Configure::GetValue(value, "test_model", test_model_);
		Configure::GetValue(value, "genesis_account", genesis_account_);
		Configure::GetValue(value, "hardfork_points", hardfork_points_);

		if (max_apply_ledger_per_round_ == 0
			|| max_trans_in_memory_ / max_apply_ledger_per_round_ == 0) {
			return false;
		}
		return true;
	}

	ValidationConfigure::ValidationConfigure() {
		close_interval_ = 3;
		threshold_ = 1;
		is_validator_ = false;
	}

	ValidationConfigure::~ValidationConfigure() {}

	bool ValidationConfigure::Load(const Json::Value &value) {

		Configure::GetValue(value, "type", type_);
		Configure::GetValue(value, "is_validator", is_validator_);
		Configure::GetValue(value, "node_private_key", node_privatekey_);
		Configure::GetValue(value, "validators", validators_);
		Configure::GetValue(value, "close_interval", close_interval_);
		Configure::GetValue(value, "threshold", threshold_);
		if ((int32_t)validators_.size() < threshold_
			|| validators_.empty()) {
			return false;
		}
		node_privatekey_ = utils::Aes::HexDecrypto(node_privatekey_, GetDataSecuretKey());
		close_interval_ = close_interval_ * utils::MICRO_UNITS_PER_SEC; //micro second
		return true;
	}

	MonitorConfigure::MonitorConfigure() {
		center_ = "127.0.0.1:4053";
		disk_path_ = "/";
		enabled_ = false;
	}

	MonitorConfigure::~MonitorConfigure() {
	}

	bool MonitorConfigure::Load(const Json::Value &value) {
		Configure::GetValue(value, "id", id_);
		Configure::GetValue(value, "center", center_);
		Configure::GetValue(value, "disk_path", disk_path_);
		Configure::GetValue(value, "enabled", enabled_);
		return true;
	}

	Configure::Configure() {}

	Configure::~Configure() {}

	bool Configure::LoadFromJson(const Json::Value &values){
		db_configure_.Load(values["db"]);
		logger_configure_.Load(values["logger"]);
		p2p_configure_.Load(values["p2p"]);
		webserver_configure_.Load(values["webserver"]);
		ledger_configure_.Load(values["ledger"]);
		validation_configure_.Load(values["validation"]);
		wsserver_configure_.Load(values["wsserver"]);
		monitor_configure_.Load(values["monitor"]);
		return true;
	}
}