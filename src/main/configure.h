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

#ifndef CONFIGURE_H_
#define CONFIGURE_H_

#include <common/configure_base.h>

namespace bubi {

	class P2pNetwork {
	public:
		P2pNetwork();
		~P2pNetwork();

		size_t target_peer_connection_;
		int64_t connect_timeout_;
		int64_t heartbeat_interval_;
		int32_t listen_port_;
		utils::StringList known_peer_list_;
		bool Load(const Json::Value &value);
	};

	class P2pConfigure {
	public:
		P2pConfigure();
		~P2pConfigure();

		std::string node_private_key_;
		int64_t network_id_;
		//CAServerConfigure ca_server_configure_;
		SSLConfigure ssl_configure_;
		P2pNetwork consensus_network_configure_;
		P2pNetwork transaction_network_configure_;

		bool Load(const Json::Value &value);
	};

	class WsServerConfigure {
	public:
		WsServerConfigure();
		~WsServerConfigure();

		utils::InetAddress listen_address_;
		bool listen_tx_status_;

		bool Load(const Json::Value &value);
	};

	class WebServerConfigure {
	public:
		WebServerConfigure();
		~WebServerConfigure();

		utils::InetAddressList listen_addresses_;

		std::string directory_;
		std::string index_name_;
		bool ssl_enable_;
		uint32_t query_limit_;
		uint32_t multiquery_limit_;
		bool remote_authorized_;
		SSLConfigure ssl_configure_;
		uint32_t thread_count_;
		bool Load(const Json::Value &value);
	};

	class LedgerConfigure {
	public:
		LedgerConfigure();
		~LedgerConfigure();

		uint32_t base_fee_;
		uint32_t base_reserve_;
		uint32_t hash_type_;
		uint32_t max_trans_per_ledger_;
		uint32_t max_ledger_per_message_;
		uint32_t max_trans_in_memory_;
		uint32_t max_apply_ledger_per_round_;
		bool test_model_;
		std::string genesis_account_;
		bool Load(const Json::Value &value);
	};

	class ValidationConfigure {
	public:
		ValidationConfigure();
		~ValidationConfigure();

		std::string type_;
		bool is_validator_;
		std::string node_privatekey_;
		utils::StringList validators_;
		int32_t threshold_;
		int64_t close_interval_;
		bool Load(const Json::Value &value);
	};

	class MonitorConfigure {
	public:
		MonitorConfigure();
		~MonitorConfigure();

		std::string connect_address_;
		std::string disk_path_;
		bool Load(const Json::Value &value);
	};

	class Configure : public ConfigureBase, public utils::Singleton<Configure> {
		friend class utils::Singleton<Configure>;
		Configure();
		~Configure();

	public:
		DbConfigure db_configure_;
		LoggerConfigure logger_configure_;

		WebServerConfigure webserver_configure_;
		WsServerConfigure wsserver_configure_; //websocket server
		
		P2pConfigure p2p_configure_;
		LedgerConfigure ledger_configure_;
		ValidationConfigure validation_configure_;

		MonitorConfigure monitor_configure_;
		//MqServerConfigure		mqserver_configure_;

		virtual bool LoadFromJson(const Json::Value &values);
	};
}

#endif