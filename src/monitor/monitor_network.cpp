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
#include <common/general.h>
#include <proto/cpp/overlay.pb.h>

#include "monitor_network.h"
#include "monitor.h"
#include "configure.h"


namespace monitor {
	MonitorNetwork::MonitorNetwork(const bubi::SslParameter &ssl_parameter_) : 
		Network(ssl_parameter_), init_(false), is_connected_(false), is_registered_(false){
		check_alert_interval_ = connect_interval_ = 5 * utils::MICRO_UNITS_PER_SEC;
		last_connect_time_ = 0;

		request_methods_[monitor::MONITOR_MSGTYPE_REGISTER] = std::bind(&MonitorNetwork::OnMonitorRegister, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_BUBI] = std::bind(&MonitorNetwork::OnMonitorInfo, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_LEDGER] = std::bind(&MonitorNetwork::OnMonitorInfo, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_SYSTEM] = std::bind(&MonitorNetwork::OnMonitorInfo, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_NOTICE] = std::bind(&MonitorNetwork::OnNoticeStatus, this, std::placeholders::_1, std::placeholders::_2);

		response_methods_[monitor::MONITOR_MSGTYPE_HELLO] = std::bind(&MonitorNetwork::OnHelloStatus, this, std::placeholders::_1, std::placeholders::_2);
		response_methods_[monitor::MONITOR_MSGTYPE_BUBI] = std::bind(&MonitorNetwork::OnMonitorInfo, this, std::placeholders::_1, std::placeholders::_2);
		response_methods_[monitor::MONITOR_MSGTYPE_SYSTEM] = std::bind(&MonitorNetwork::OnMonitorInfo, this, std::placeholders::_1, std::placeholders::_2);
		response_methods_[monitor::MONITOR_MSGTYPE_ALERT] = std::bind(&MonitorNetwork::OnAlertStatus, this, std::placeholders::_1, std::placeholders::_2);
		response_methods_[monitor::MONITOR_MSGTYPE_LEDGER] = std::bind(&MonitorNetwork::OnMonitorInfo, this, std::placeholders::_1, std::placeholders::_2);
	}

	bool MonitorNetwork::Initialize() {
		monitor::MonitorConfigure& monitor_configure = Configure::Instance().monitor_configure_;
		monitor_id_ = monitor_configure.id_;

		TimerNotify::RegisterModule(this);
		init_ = true;
		return true;
	}

	bool MonitorNetwork::Exit() {
		//join and wait
		LOG_INFO("close async OK");
		init_ = false;
		return true;
	}

	bool MonitorNetwork::OnConnectOpen(bubi::Connection *conn) {
		bool bret = true;
		const MonitorConfigure& monitor_configure = Configure::Instance().monitor_configure_;
		if (!conn->InBound()) {
			is_connected_ = true;

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
		}
		else {
			Monitor *monitor = (Monitor*)conn;
			std::error_code ignore_ec;
			protocol::ChainHello hello;
			hello.set_timestamp(utils::Timestamp::HighResolution());
			if (!monitor->SendRequest(monitor::MONITOR_MSGTYPE_HELLO, hello.SerializeAsString(), ignore_ec)) {
				LOG_ERROR("Send bubi hello from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIpPort().c_str(),
					ignore_ec.value(), ignore_ec.message().c_str());
			}
			
		}
		return bret;
	}

	void MonitorNetwork::OnDisconnect(bubi::Connection *conn) {
		Monitor *monitor = (Monitor*)conn;
		monitor->SetActiveTime(0);
		if (!conn->InBound()) {
			is_connected_ = false;
			is_registered_ = false;
			alert_.ResetState();
			notice_.ResetState();
		}
	}

	bubi::Connection * MonitorNetwork::CreateConnectObject(bubi::server *server_h, bubi::client *client_, bubi::tls_server *tls_server_h, 
		bubi::tls_client *tls_client_h, bubi::connection_hdl con, const std::string &uri, int64_t id) {
		return new Monitor(server_h, client_, tls_server_h, tls_client_h, con, uri, id);
	}

	bool MonitorNetwork::NodeExist(std::string node_address, int64_t peer_id) {
		bool exist = false;
		for (bubi::ConnectionMap::iterator iter = connections_.begin(); iter != connections_.end(); iter++) {
			Monitor *monitor = (Monitor *)iter->second;
			if (monitor->GetPeerNodeAddress() == node_address && iter->second->GetId() != peer_id) {
				exist = true;
				break;
			}
		}
		return exist;
	}

	bubi::Connection* MonitorNetwork::GetServerConnection() {
		bubi::Connection* monitor = NULL;
		utils::MutexGuard guard(conns_list_lock_);
		for (auto item : connections_) {
			Monitor *peer = (Monitor *)item.second;
			if (peer->IsActive() && peer->InBound()) {
				monitor = peer;
				break;
			}
		}

		return monitor;
	}

	bubi::Connection * MonitorNetwork::GetClientConnection() {
		bubi::Connection* monitor = NULL;
		utils::MutexGuard guard(conns_list_lock_);
		for (auto item : connections_) {
			Monitor *peer = (Monitor *)item.second;
			if (peer->IsActive() && !peer->InBound()) {
				monitor = peer;
				break;
			}
		}

		return monitor;
	}

	bool MonitorNetwork::OnMonitorRegister(protocol::WsMessage &message, int64_t conn_id) {
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

			monitor::Threshold threshold = reg.threshold();
			if (threshold.monitor_timeout() != 0) {
				connect_time_out_ = threshold.monitor_timeout() * utils::MICRO_UNITS_PER_SEC;
			}
			if (fabs(threshold.cpu()) > 1e-7) {
				alert_.SetCpuCriticality(threshold.cpu());
			}
			if (fabs(threshold.memory()) > 1e-7) {
				alert_.SetMemoryCriticality(threshold.memory());
			}
			if (fabs(threshold.disk()) > 1e-7) {
				alert_.SetDiskCriticality(threshold.disk());
			}
			if (threshold.consensus_timeout() != 0) {
				alert_.SetConsensusTime(threshold.consensus_timeout());
			}
			if (threshold.bubi_timeout() != 0) {
				alert_.SetBubiCrackTime(threshold.bubi_timeout());
			}
			monitor::BubiAttack bubi_attack;
			if (threshold.has_bubi_attack()) {
				bubi_attack = threshold.bubi_attack();
				if (bubi_attack.bubi_attack_time() != 0) {
					notice_.SetBubiAttackTime(bubi_attack.bubi_attack_time());
				}
				if (bubi_attack.bubi_attack_counts() != 0) {
					notice_.SetBubiAttackCounts(bubi_attack.bubi_attack_time());
				}
			}
			std::error_code ignore_ec;
			monitor::Monitor *monitor = (monitor::Monitor*)GetConnection(conn_id);
			monitor->SetSessionId(session_id);
			monitor->SetActiveTime(utils::Timestamp::HighResolution());
			
			if (!monitor->SendResponse(message, "", ignore_ec)) {
				LOG_ERROR("Send register from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIp().c_str(),
					ignore_ec.value(), ignore_ec.message().c_str());
				break;
			}
			is_registered_ = true;
			bret = true;
		} while (false);

		
		return bret;
	}

	bool MonitorNetwork::OnMonitorInfo(protocol::WsMessage &message, int64_t conn_id) {
		monitor::Monitor *monitor = (monitor::Monitor *)GetConnection(conn_id);
		if (!is_registered_) {
			LOG_ERROR("monitor center(%s) is not registered", monitor->GetRemoteAddress().ToIpPort().c_str());
			return false;
		}

		if (!monitor->InBound()) {
			monitor::Monitor *server = (monitor::Monitor *)GetServerConnection();
			if (server != NULL && server->IsActive()) {
				std::error_code ignore_ec;
				if (!server->SendRequest(message.type(), message.data(), ignore_ec)) {
					LOG_ERROR("Send bubi request from ip(%s) failed (%d:%s)", server->GetPeerAddress().ToIp().c_str(),
						ignore_ec.value(), ignore_ec.message().c_str());
					return false;
				}
			}
		}
		else {
			Monitor* client = (Monitor*)GetClientConnection();
			if (client != NULL && client->IsActive()) {
				std::error_code ignore_ec;
				if (!client->SendResponse(message, message.data(), ignore_ec)) {
					LOG_ERROR("Send monitor info from ip(%s) failed (%d:%s)", client->GetPeerAddress().ToIp().c_str(),
						ignore_ec.value(), ignore_ec.message().c_str());
					return false;
				}
			}
		}
		
		return true;
	}

	bool MonitorNetwork::OnHelloStatus(protocol::WsMessage &message, int64_t conn_id) {
		bool bret = false;
		protocol::ChainStatus hello;
		hello.ParseFromString(message.data());
		monitor::Monitor *monitor = (monitor::Monitor*)GetConnection(conn_id);

		do {
			if (NodeExist(hello.self_addr(), monitor->GetId())) {
				LOG_ERROR("disconnect duplicated bubi with %s", monitor->GetPeerAddress().ToIp().c_str());
				break;
			}

			if (hello.monitor_version() < bubi::General::MONITOR_VERSION) {
				LOG_ERROR("bubi's monitor version(%d) is too old,", hello.monitor_version());
				break;
			}

			LOG_INFO("Recv hello, bubi(%s) is active", monitor->GetRemoteAddress().ToIpPort().c_str());
			monitor->SetBubiInfo(hello);
			monitor->SetActiveTime(utils::Timestamp::HighResolution());

			bret = true;
		} while (false);

		return bret;
	}

	bool MonitorNetwork::OnAlertStatus(protocol::WsMessage &message, int64_t conn_id) {
		bool bret = false;
		do {
			monitor::Monitor *monitor = (monitor::Monitor*)GetConnection(conn_id);
			if (monitor->InBound()) {
				monitor::ChainAlertMessage alert_status;
				if (!alert_status.ParseFromString(message.data())) {
					break;
				}

				alert_.SetBubiLastTime(utils::Timestamp::HighResolution());
				alert_.SetBuffer(alert_status);
			}
		} while (false);
		return true;
	}

	bool MonitorNetwork::OnNoticeStatus(protocol::WsMessage &message, int64_t conn_id) {

		return true;
	}

	void MonitorNetwork::OnTimer(int64_t current_time) {
		if (current_time - last_connect_time_ > connect_interval_) {
			if (!is_connected_ && init_) {
				std::string uri = utils::String::Format("%s://%s", ssl_parameter_.enable_ ? "wss" : "ws", Configure::Instance().monitor_configure_.server_address_.c_str());
				Connect(uri);
			}
			last_connect_time_ = current_time;
		}
	}

	void MonitorNetwork::OnSlowTimer(int64_t current_time) {
		do {
			if (!is_registered_) break;

			
			if (current_time - check_alert_interval_ > last_alert_time_) {
				// send alert request
				monitor::ChainAlertMessage alert_info;
				bubi::Connection* server = GetServerConnection();
				if (server != NULL) {
					std::error_code ignore_ec;
					if (!server->SendRequest(monitor::MONITOR_MSGTYPE_ALERT, alert_info.SerializeAsString(), ignore_ec)) {
						LOG_ERROR("Send bubi alert from ip(%s) failed (%d:%s)", server->GetPeerAddress().ToIp().c_str(),
							ignore_ec.value(), ignore_ec.message().c_str());
					}
				}
				last_alert_time_ = current_time;
			}

			// check alert
			monitor::AlertStatus alert_status;
			if (alert_.CheckAlert(alert_status)) {
				try {
					std::error_code ignore_ec;
					monitor::Monitor *monitor = (monitor::Monitor *)GetClientConnection();
					if (!monitor->SendRequest(monitor::MONITOR_MSGTYPE_ALERT, alert_status.SerializeAsString(), ignore_ec)) {
						LOG_ERROR("Send monitor alert from ip(%s) failed (%d:%s)", monitor->GetPeerAddress().ToIp().c_str(),
							ignore_ec.value(), ignore_ec.message().c_str());
						break;
					}
					LOG_INFO("OnSlowTimer -- start send warning");
				}
				catch (std::exception& e) {
					LOG_ERROR("OnSlowTimer -- %s", e.what());
				}
			}

			// check transactions exceptions
			//result.clear();
			//if (notice_.CheckTxException(result)) {
			//	try {
			//		result["session_id"] = random_key_;
			//		SendRequestMessage("block_status", true, result);
			//		LOG_INFO("OnSlowTimer -- start send warning: %s", result.toFastString().c_str());
			//	}
			//	catch (std::exception& e) {
			//		LOG_ERROR("OnSlowTimer -- %s", e.what());
			//	}
			//}
		} while (false);
	}
}