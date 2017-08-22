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

#include <utils/headers.h>
#include <common/general.h>
#include <main/configure.h>
#include <proto/cpp/monitor.pb.h>
#include <overlay/peer_manager.h>
#include <glue/glue_manager.h>
#include <ledger/ledger_manager.h>
#include <monitor/monitor.h>

#include "websocket_server.h"

namespace bubi {
	WebSocketServer::WebSocketServer() : Network(SslParameter()) {
		connect_interval_ = 120 * utils::MICRO_UNITS_PER_SEC;
		last_connect_time_ = 0;

		request_methods_[protocol::CHAIN_HELLO] = std::bind(&WebSocketServer::OnChainHello, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[protocol::CHAIN_PEER_MESSAGE] = std::bind(&WebSocketServer::OnChainPeerMessage, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[protocol::CHAIN_SUBMITTRANSACTION] = std::bind(&WebSocketServer::OnSubmitTransaction, this, std::placeholders::_1, std::placeholders::_2);

		request_methods_[monitor::MONITOR_MSGTYPE_HELLO] = std::bind(&WebSocketServer::OnChainHello, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_BUBI] = std::bind(&WebSocketServer::OnBubiStatus, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_LEDGER] = std::bind(&WebSocketServer::OnLedgerStatus, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_SYSTEM] = std::bind(&WebSocketServer::OnSystemStatus, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_ALERT] = std::bind(&WebSocketServer::OnAlertStatus, this, std::placeholders::_1, std::placeholders::_2);

		thread_ptr_ = NULL;
		init_ = false;
	}

	WebSocketServer::~WebSocketServer() {
		if (thread_ptr_){
			delete thread_ptr_;
		} 
	}

	bool WebSocketServer::Initialize(WsServerConfigure &ws_server_configure) {
		thread_ptr_ = new utils::Thread(this);
		if (!thread_ptr_->Start("websocket")) {
			return false;
		}

		init_ = true;
		StatusModule::RegisterModule(this);
		TimerNotify::RegisterModule(this);
		LOG_INFO("Websocket server initialized");
		return true;
	}

	bool WebSocketServer::Exit() {
		Stop();
		thread_ptr_->JoinWithStop();
		return true;
	}

	void WebSocketServer::Run(utils::Thread *thread) {
		Start(bubi::Configure::Instance().wsserver_configure_.listen_address_);
	}

	void WebSocketServer::OnDisconnect(Connection *conn) {
		is_connected_ = false;
	}

	bool WebSocketServer::OnConnectOpen(Connection *conn) {
		is_connected_ = true;
		return true;
	}

	bool WebSocketServer::OnChainHello(protocol::WsMessage &message, int64_t conn_id) {
		protocol::ChainStatus cmsg;
		cmsg.set_bubi_version(General::BUBI_VERSION);
		cmsg.set_monitor_version(General::MONITOR_VERSION);
		cmsg.set_ledger_version(General::LEDGER_VERSION);
		cmsg.set_self_addr(PeerManager::Instance().GetPeerNodeAddress());
		cmsg.set_timestamp(utils::Timestamp::HighResolution());
		std::error_code ignore_ec;

		utils::MutexGuard guard_(conns_list_lock_);
		Connection *conn = GetConnection(conn_id);
		if (conn) {
			conn->SendResponse(message, cmsg.SerializeAsString(), ignore_ec);
			LOG_INFO("Recv chain hello from ip(%s), send response result(%d:%s)", conn->GetPeerAddress().ToIpPort().c_str(),
				ignore_ec.value(), ignore_ec.message().c_str());
		}
		return true;
	}

	bool WebSocketServer::OnChainPeerMessage(protocol::WsMessage &message, int64_t conn_id) {
		// send peer
		utils::MutexGuard guard_(conns_list_lock_);
		Connection *conn = GetConnection(conn_id);
		if (!conn) {
			return false;
		}

		LOG_INFO("Recv chain peer message from ip(%s)", conn->GetPeerAddress().ToIpPort().c_str());
		protocol::ChainPeerMessage cpm;
		if (!cpm.ParseFromString(message.data())) {
			LOG_ERROR("ChainPeerMessage FromString fail");
			return true;
		}

		//bubi::PeerManager::Instance().BroadcastPayLoad(cpm);
		return true;
	}

	void WebSocketServer::BroadcastMsg(int64_t type, const std::string &data) {
		utils::MutexGuard guard(conns_list_lock_);

		for (ConnectionMap::iterator iter = connections_.begin();
			iter != connections_.end();
			iter++) {
			std::error_code ec;
			iter->second->SendRequest(type, data, ec);
		}
	}

	bool WebSocketServer::SendMonitor(int64_t type, const std::string &data) {
		bool bret = true;
		utils::MutexGuard guard(conns_list_lock_);
		for (auto item : connections_) {
			std::error_code ignore_ec;
			Connection *peer = item.second;
			if (!peer->InBound()) {
				if (!peer->SendRequest(type, data, ignore_ec)) {
					bret = false;
					LOG_ERROR("Send monitor from ip(%s) failed (%d:%s)", peer->GetPeerAddress().ToIpPort().c_str(),
						ignore_ec.value(), ignore_ec.message().c_str());
				}
			}
		}
		return bret;
	}

	void WebSocketServer::BroadcastChainTxMsg(const std::string &hash, const std::string &source_address, Result result, protocol::ChainTxStatus_TxStatus status) {
		protocol::ChainTxStatus cts;
		cts.set_tx_hash(utils::String::BinToHexString(hash));
		cts.set_source_address(source_address);
		cts.set_error_code((protocol::ERRORCODE)result.code());
		cts.set_error_desc(result.desc());
		cts.set_status(status);
		cts.set_timestamp(utils::Timestamp::Now().timestamp());
		std::string str = cts.SerializeAsString();
		bubi::WebSocketServer::Instance().BroadcastMsg(protocol::CHAIN_TX_STATUS, str);
	}

	bool WebSocketServer::OnSubmitTransaction(protocol::WsMessage &message, int64_t conn_id) {
		utils::MutexGuard guard_(conns_list_lock_);
		Connection *conn = GetConnection(conn_id);
		if (!conn) {
			return false;
		}

		Result result;
		protocol::TransactionEnv tran_env;
		do {
			if (!tran_env.ParseFromString(message.data())) {
				LOG_ERROR("Parse submit transaction string fail, ip(%s)", conn->GetPeerAddress().ToIpPort().c_str());
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc("Parse the transaction failed");
				break;
			}
			Json::Value real_json;
			real_json = Proto2Json(tran_env);
			printf(real_json.toStyledString().c_str());
			std::string content = tran_env.transaction().SerializeAsString();

			// add node signature
			PrivateKey privateKey(bubi::Configure::Instance().p2p_configure_.node_private_key_);
			if (!privateKey.IsValid()) {
				result.set_code(protocol::ERRCODE_INVALID_PRIKEY);
				result.set_desc("Node signature failed");
				LOG_ERROR("Node private key is invalid");
				break;
			}
			std::string sign = privateKey.Sign(content);
			protocol::Signature *signpro = tran_env.add_signatures();
			signpro->set_sign_data(sign);
			signpro->set_public_key(privateKey.GetBase16PublicKey());

			TransactionFrm::pointer ptr = std::make_shared<TransactionFrm>(tran_env);
			GlueManager::Instance().OnTransaction(ptr, result);
			PeerManager::Instance().Broadcast(protocol::OVERLAY_MSGTYPE_TRANSACTION, tran_env.SerializeAsString());
		
		} while (false);

		//notice WebSocketServer Tx status
		std::string hash = HashWrapper::Crypto(tran_env.transaction().SerializeAsString());
		protocol::ChainTxStatus cts;
		cts.set_tx_hash(utils::String::BinToHexString(hash));
		cts.set_error_code((protocol::ERRORCODE)result.code());
		cts.set_source_address(tran_env.transaction().source_address());
		cts.set_status(result.code() == protocol::ERRCODE_SUCCESS ? protocol::ChainTxStatus_TxStatus_CONFIRMED : protocol::ChainTxStatus_TxStatus_FAILURE);
		cts.set_error_desc(result.desc());
		cts.set_timestamp(utils::Timestamp::Now().timestamp());
		std::string str = cts.SerializeAsString();
			
		BroadcastMsg(protocol::CHAIN_TX_STATUS, str);
		
		return true;
	}

	bool WebSocketServer::OnBubiStatus(protocol::WsMessage &message, int64_t conn_id) {
		monitor::BubiStatus bubi_status;
		GetBubiStatus(bubi_status);

		bool bret = true;
		std::error_code ignore_ec;
		Connection *monitor = GetConnection(conn_id);
		if (!monitor->SendResponse(message, bubi_status.SerializeAsString(), ignore_ec)) {
			bret = false;
			LOG_ERROR("Send bubi status from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIpPort().c_str(),
				ignore_ec.value(), ignore_ec.message().c_str());
		}
		return bret;
	}

	bool WebSocketServer::OnLedgerStatus(protocol::WsMessage &message, int64_t conn_id) {
		monitor::LedgerStatus ledger_status;
		ledger_status.mutable_ledger_header()->CopyFrom(LedgerManager::Instance().GetLastClosedLedger());
		ledger_status.set_transaction_size(0);
		ledger_status.set_account_count(0);
		ledger_status.set_timestamp(utils::Timestamp::HighResolution());

		bool bret = true;
		std::error_code ignore_ec;
		Connection *monitor = GetConnection(conn_id);
		if (!monitor->SendResponse(message, ledger_status.SerializeAsString(), ignore_ec)) {
			bret = false;
			LOG_ERROR("Send ledger status from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIpPort().c_str(),
				ignore_ec.value(), ignore_ec.message().c_str());
		}
		return bret;
	}

	bool WebSocketServer::OnSystemStatus(protocol::WsMessage &message, int64_t conn_id) {
		monitor::SystemStatus* system_status = new monitor::SystemStatus();
		std::string disk_paths = Configure::Instance().monitor_configure_.disk_path_;
		system_manager_.GetSystemMonitor(disk_paths, system_status);

		bool bret = true;
		std::error_code ignore_ec;
		Connection *monitor = GetConnection(conn_id);
		if (!monitor->SendResponse(message, system_status->SerializeAsString(), ignore_ec)) {
			bret = false;
			LOG_ERROR("Send system status from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIpPort().c_str(),
				ignore_ec.value(), ignore_ec.message().c_str());
		}
		if (system_status) {
			delete system_status;
			system_status = NULL;
		}
		return bret;
	}

	bool WebSocketServer::OnAlertStatus(protocol::WsMessage &message, int64_t conn_id) {
		monitor::ChainAlertMessage alert_status;
		alert_status.set_ledger_sequence(LedgerManager::Instance().GetLastClosedLedger().seq());
		alert_status.set_node_id(PeerManager::Instance().GetPeerNodeAddress());
		monitor::SystemStatus *system_status = alert_status.mutable_system();
		std::string disk_paths = Configure::Instance().monitor_configure_.disk_path_;
		system_manager_.GetSystemMonitor(disk_paths, system_status);

		bool bret = true;
		std::error_code ignore_ec;
		Connection *monitor = GetConnection(conn_id);
		if (!monitor->SendResponse(message, alert_status.SerializeAsString(), ignore_ec)) {
			bret = false;
			LOG_ERROR("Send alert status from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIpPort().c_str(),
				ignore_ec.value(), ignore_ec.message().c_str());
		}
		return bret;
	}


	void WebSocketServer::GetModuleStatus(Json::Value &data) {
		data["name"] = "websocket_server";
		Json::Value &peers = data["clients"];
		int32_t active_size = 0;
		utils::MutexGuard guard(conns_list_lock_);
		for (auto &item : connections_) {
			item.second->ToJson(peers[peers.size()]);
		}
	}

	void WebSocketServer::OnTimer(int64_t current_time) {
		// reconnect if disconnect
		if (current_time - last_connect_time_ > connect_interval_) {
			if (!is_connected_ && init_) {
				std::string url = utils::String::Format("ws://%s", Configure::Instance().monitor_configure_.connect_address_.c_str());
				Connect(url);
			}
			last_connect_time_ = current_time;
		}
	}

	void WebSocketServer::OnSlowTimer(int64_t current_time) {
		system_manager_.OnSlowTimer(current_time);
	}

	bool WebSocketServer::GetBubiStatus(monitor::BubiStatus &bubi_status) {
		time_t process_uptime = GlueManager::Instance().GetProcessUptime();
		utils::Timestamp time_stamp(utils::GetStartupTime() * utils::MICRO_UNITS_PER_SEC);
		utils::Timestamp process_time_stamp(process_uptime * utils::MICRO_UNITS_PER_SEC);

		monitor::GlueManager *glue_manager = bubi_status.mutable_glue_manager();
		glue_manager->set_system_uptime(time_stamp.ToFormatString(false));
		glue_manager->set_process_uptime(process_time_stamp.ToFormatString(false));
		glue_manager->set_system_current_time(utils::Timestamp::Now().ToFormatString(false));

		monitor::PeerManager *peer_manager = bubi_status.mutable_peer_manager();
		peer_manager->set_peer_id(PeerManager::Instance().GetPeerNodeAddress());

		bubi::ConnectionMap connections = PeerManager::Instance().ConsensusNetwork().GetPeers();
		for (auto &item : connections) {
			monitor::Peer *peer = peer_manager->add_peer();
			bubi::Peer *conn = (bubi::Peer *)item.second;
			if (conn->IsActive()) {
				peer->set_id(conn->GetPeerNodeAddress());
				peer->set_delay(conn->GetDelay());
				peer->set_ip_address(conn->GetPeerAddress().ToIpPort());
				peer->set_active(conn->IsActive());
			}
		}
		return true;
	}
}