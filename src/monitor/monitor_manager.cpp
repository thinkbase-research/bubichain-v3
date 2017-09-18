///*
//Copyright Bubi Technologies Co., Ltd. 2017 All Rights Reserved.
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//http://www.apache.org/licenses/LICENSE-2.0
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//*/
//
#include <utils/headers.h>
#include <common/general.h>
#include <main/configure.h>
#include <proto/cpp/monitor.pb.h>
#include <overlay/peer_manager.h>
#include <glue/glue_manager.h>
#include <ledger/ledger_manager.h>
#include <monitor/monitor.h>

#include "monitor_manager.h"

namespace bubi {
	MonitorManager::MonitorManager() : Network(SslParameter()) {
		connect_interval_ = 120 * utils::MICRO_UNITS_PER_SEC;
		check_alert_interval_ = 5 * utils::MICRO_UNITS_PER_SEC;
		last_connect_time_ = 0;

		request_methods_[monitor::MONITOR_MSGTYPE_REGISTER] = std::bind(&MonitorManager::OnMonitorRegister, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_BUBI] = std::bind(&MonitorManager::OnBubiStatus, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_LEDGER] = std::bind(&MonitorManager::OnLedgerStatus, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_SYSTEM] = std::bind(&MonitorManager::OnSystemStatus, this, std::placeholders::_1, std::placeholders::_2);

		thread_ptr_ = NULL;
	}

	MonitorManager::~MonitorManager() {
		if (thread_ptr_){
			delete thread_ptr_;
		} 
	}

	bool MonitorManager::Initialize() {
		MonitorConfigure& monitor_configure = Configure::Instance().monitor_configure_;
		monitor_id_ = monitor_configure.id_;

		thread_ptr_ = new utils::Thread(this);
		if (!thread_ptr_->Start("monitor")) {
			return false;
		}

		StatusModule::RegisterModule(this);
		TimerNotify::RegisterModule(this);
		LOG_INFO("monitor manager initialized");
		return true;
	}

	bool MonitorManager::Exit() {
		Stop();
		thread_ptr_->JoinWithStop();
		return true;
	}

	void MonitorManager::Run(utils::Thread *thread) {
		Start(utils::InetAddress::None());
	}

	bool MonitorManager::OnConnectOpen(Connection *conn) {
		std::error_code ignore_ec;
		Monitor *monitor = (Monitor*)conn;
		monitor::Hello hello;
		hello.set_id(utils::MD5::GenerateMD5((unsigned char*)monitor_id_.c_str(), monitor_id_.length()));
		hello.set_blockchain_version(bubi::General::BUBI_VERSION);
		hello.set_data_version(bubi::General::MONITOR_VERSION);
		hello.set_timestamp(utils::Timestamp::HighResolution());
		if (!monitor->SendRequest(monitor::MONITOR_MSGTYPE_HELLO, hello.SerializeAsString(), ignore_ec)) {
			LOG_ERROR("Send hello from monitor ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIpPort().c_str(),
				ignore_ec.value(), ignore_ec.message().c_str());
		}
		return true;
	}

	bubi::Connection * MonitorManager::CreateConnectObject(bubi::server *server_h, bubi::client *client_, bubi::tls_server *tls_server_h, 
		bubi::tls_client *tls_client_h, bubi::connection_hdl con, const std::string &uri, int64_t id) {
		return new Monitor(server_h, client_, tls_server_h, tls_client_h, con, uri, id);
	}

	void MonitorManager::OnDisconnect(Connection *conn) {
		Monitor *monitor = (Monitor *)conn;
		monitor->SetActiveTime(0);
	}

	bool MonitorManager::SendMonitor(int64_t type, const std::string &data) {
		bool bret = false;
		do {
			Monitor *monitor = (Monitor *)GetClientConnection();
			if (NULL == monitor || !monitor->IsActive()) {
				break;
			}

			std::error_code ignore_ec;
			if (!monitor->SendRequest(type, data, ignore_ec)) {
				LOG_ERROR("Send monitor(type: %d) from ip(%s) failed (%d:%s)", type, monitor->GetPeerAddress().ToIpPort().c_str(),
					ignore_ec.value(), ignore_ec.message().c_str());
				break;
			}
			bret = true;
		} while (false);
		
		return bret;
	}

	bool MonitorManager::OnMonitorRegister(protocol::WsMessage &message, int64_t conn_id) {
		bool bret = false;
		do {
			monitor::Register reg;
			if (!reg.ParseFromString(message.data())) {
				break;
			}

			std::string session_id = reg.session_id();
			std::string rand_id = reg.rand_id();
			std::string md_id = monitor_id_ + session_id;
			if (rand_id.compare(utils::MD5::GenerateMD5((unsigned char*)md_id.c_str(), md_id.length())) != 0) {
				break;
			}

			std::string version = reg.version();
			int64_t reg_time = reg.timestamp();

			std::error_code ignore_ec;
			Monitor *monitor = (Monitor*)GetConnection(conn_id);
			if (!monitor->SendResponse(message, "", ignore_ec)) {
				LOG_ERROR("Send register from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIp().c_str(),
					ignore_ec.value(), ignore_ec.message().c_str());
				break;
			}
			monitor->SetSessionId(session_id);
			monitor->SetActiveTime(utils::Timestamp::HighResolution());

			bret = true;
		} while (false);


		return bret;
	}

	bool MonitorManager::OnBubiStatus(protocol::WsMessage &message, int64_t conn_id) {
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

	bool MonitorManager::OnLedgerStatus(protocol::WsMessage &message, int64_t conn_id) {
		monitor::LedgerStatus ledger_status;
		ledger_status.mutable_ledger_header()->CopyFrom(LedgerManager::Instance().GetLastClosedLedger());
		ledger_status.set_transaction_size(0);
		ledger_status.set_account_count(0);
		ledger_status.set_timestamp(utils::Timestamp::HighResolution());

		bool bret = true;
		std::error_code ignore_ec;
		Monitor *monitor = (Monitor *)GetConnection(conn_id);
		if (monitor != NULL || monitor->IsActive()) {
			if (!monitor->SendResponse(message, ledger_status.SerializeAsString(), ignore_ec)) {
				bret = false;
				LOG_ERROR("Send ledger status from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIpPort().c_str(),
					ignore_ec.value(), ignore_ec.message().c_str());
			}
		}
		return bret;
	}

	bool MonitorManager::OnSystemStatus(protocol::WsMessage &message, int64_t conn_id) {
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

	Connection * MonitorManager::GetClientConnection() {
		bubi::Connection* monitor = NULL;
		utils::MutexGuard guard(conns_list_lock_);
		for (auto item : connections_) {
			Monitor *peer = (Monitor *)item.second;
			if (!peer->InBound()) {
				monitor = peer;
				break;
			}
		}

		return monitor;
	}


	void MonitorManager::GetModuleStatus(Json::Value &data) {
		data["name"] = "monitor_manager";
		Json::Value &peers = data["clients"];
		int32_t active_size = 0;
		utils::MutexGuard guard(conns_list_lock_);
		for (auto &item : connections_) {
			item.second->ToJson(peers[peers.size()]);
		}
	}

	void MonitorManager::OnTimer(int64_t current_time) {
		// reconnect if disconnect
		if (current_time - last_connect_time_ > connect_interval_) {
			Monitor *monitor = (Monitor *)GetClientConnection();
			if (NULL == monitor) {
				std::string url = utils::String::Format("ws://%s", Configure::Instance().monitor_configure_.center_.c_str());
				Connect(url);
			}
			last_connect_time_ = current_time;
		}
	}

	void MonitorManager::OnSlowTimer(int64_t current_time) {
		Monitor *monitor = (Monitor *)GetClientConnection();
		if (monitor == NULL || !monitor->IsActive()) {
			return;
		}

		system_manager_.OnSlowTimer(current_time);

		// send alert
		if (current_time - check_alert_interval_ > last_alert_time_) {
			monitor::AlertStatus alert_status;
			alert_status.set_ledger_sequence(LedgerManager::Instance().GetLastClosedLedger().seq());
			alert_status.set_node_id(PeerManager::Instance().GetPeerNodeAddress());
			monitor::SystemStatus *system_status = alert_status.mutable_system();
			std::string disk_paths = Configure::Instance().monitor_configure_.disk_path_;
			system_manager_.GetSystemMonitor(disk_paths, system_status);

			bool bret = true;
			std::error_code ignore_ec;
			if (!monitor->SendRequest(monitor::MONITOR_MSGTYPE_ALERT, alert_status.SerializeAsString(), ignore_ec)) {
				bret = false;
				LOG_ERROR("Send alert status from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIpPort().c_str(),
					ignore_ec.value(), ignore_ec.message().c_str());
			}

			last_alert_time_ = current_time;
		}
	}

	bool MonitorManager::GetBubiStatus(monitor::BubiStatus &bubi_status) {
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