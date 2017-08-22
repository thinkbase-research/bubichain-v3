#include "monitor_client.h"
#include "monitor.h"
#include "system_manager.h"
#include <common/general.h>
#include <proto/cpp/monitor.pb.h>
#include <ledger/ledger_manager.h>
#include <ledger/ledger_frm.h>
#include <glue/glue_manager.h>
#include <overlay/peer_manager.h>
#include <main/configure.h>

namespace bubi {
	MonitorClient::MonitorClient() : Network(SslParameter()), is_connected_(false), init_(false) {
		connect_interval_ = 5 * utils::MICRO_UNITS_PER_SEC;
		last_connect_time_ = 0;
		request_methods_[monitor::MONITOR_MSGTYPE_BUBI] = std::bind(&MonitorClient::OnMethodBubi, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_LEDGER] = std::bind(&MonitorClient::OnMethodLedger, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_SYSTEM] = std::bind(&MonitorClient::OnMethodSystem, this, std::placeholders::_1, std::placeholders::_2);
		request_methods_[monitor::MONITOR_MSGTYPE_ALERT] = std::bind(&MonitorClient::OnMethodAlert, this, std::placeholders::_1, std::placeholders::_2);
	}

	MonitorClient::~MonitorClient() {
	}

	bool MonitorClient::Initialize() {
		bool bret = false;
		do {
			thread_ptr_ = new utils::Thread(this);
			if (!thread_ptr_->Start("monitor_client")) {
				break;
			}

			TimerNotify::RegisterModule(this);
			init_ = true;
			bret = true;
			LOG_INFO("Websocket server initialized");
		} while (false);
		
		return bret;
	}

	bool MonitorClient::Exit() {
		init_ = false;
		Stop();
		thread_ptr_->JoinWithStop();
		if (thread_ptr_){
			delete thread_ptr_;
		}
		return true;
	}

	void MonitorClient::Run(utils::Thread *thread) {
		Start(utils::InetAddress::None());
	}

	void MonitorClient::OnDisconnect(Connection *conn){
		is_connected_ = false;
	}

	bool MonitorClient::OnConnectOpen(Connection *conn) {
		is_connected_ = true;
		const P2pNetwork &p2p_configure = Configure::Instance().p2p_configure_.consensus_network_configure_;
		monitor::Monitor *monitor = (monitor::Monitor*)conn;
		monitor->SendHello(p2p_configure.listen_port_, peer_node_address_, last_ec_);
		return true;
	}

	Connection * MonitorClient::CreateConnectObject(server *server_h, client *client_, tls_server *tls_server_h, tls_client *tls_client_h, connection_hdl con, const std::string &uri, int64_t id) {
		return new monitor::Monitor(server_h, client_, tls_server_h, tls_client_h, con, uri, id);
	}
	
	bool MonitorClient::OnMethodBubi(protocol::WsMessage &message, int64_t conn_id) {
		monitor::Monitor *monitor = (monitor::Monitor*)GetConnection(conn_id);

		monitor::RequestBubi request_bubi;
		if (!request_bubi.ParseFromString(message.data())) {
			return false;
		}
		session_id_ = request_bubi.session_id();

		monitor::BubiStatus bubi_status;
		GetBubiStatus(bubi_status);

		return monitor->SendResponse(message, bubi_status.SerializeAsString(), last_ec_);
	}

	bool MonitorClient::OnMethodLedger(protocol::WsMessage &message, int64_t conn_id) {
		monitor::Monitor *monitor = (monitor::Monitor*)GetConnection(conn_id);
		monitor::RequestLedger request_ledger;
		if (!request_ledger.ParseFromString(message.data())) {
			return false;
		}
		session_id_ = request_ledger.session_id();

		monitor::LedgerStatus ledger_status;
		if (!GetLedgerStatus(request_ledger.seq(), request_ledger.num(), ledger_status)) {
			return false;
		}

		ledger_status.set_session_id(session_id_);

		return monitor->SendResponse(message, ledger_status.SerializeAsString(), last_ec_);
	}

	bool MonitorClient::OnMethodSystem(protocol::WsMessage &message, int64_t conn_id) {
		monitor::RequestSystem request_system;
		if (!request_system.ParseFromString(message.data())) {
			return false;
		}
		session_id_ = request_system.session_id();

		monitor::SystemStatus system_status;
		std::string disk_paths = Configure::Instance().monitor_configure_.disk_path_;
		system_manager_.GetSystemMonitor(disk_paths, system_status);
		system_status.set_session_id(session_id_);

		monitor::Monitor *monitor = (monitor::Monitor*)GetConnection(conn_id);
		return monitor->SendResponse(message, system_status.SerializeAsString(), last_ec_);
	}

	bool MonitorClient::OnMethodAlert(protocol::WsMessage &message, int64_t conn_id) {
		bool bret = false;
		monitor::AlertInfo alert_status;
		if (!alert_status.ParseFromString(message.data())) {
			return false;
		}
		session_id_ = alert_status.session_id();
		alert_status.set_ledger_sequence(LedgerManager::Instance().GetLastClosedLedger().seq());
		alert_status.set_node_id(peer_node_address_);
		monitor::SystemStatus system_status;
		std::string disk_paths = Configure::Instance().monitor_configure_.disk_path_;
		system_manager_.GetSystemMonitor(disk_paths, system_status);
		alert_status.set_allocated_system(&system_status);

		monitor::Monitor *monitor = (monitor::Monitor*)GetConnection(conn_id);
		return monitor->SendResponse(message, alert_status.SerializeAsString(), last_ec_);
	}

	bool MonitorClient::GetBubiStatus(monitor::BubiStatus &bubi_status) {
		time_t process_uptime = GlueManager::Instance().GetProcessUptime();
		utils::Timestamp time_stamp(utils::GetStartupTime() * utils::MICRO_UNITS_PER_SEC);
		utils::Timestamp process_time_stamp(process_uptime * utils::MICRO_UNITS_PER_SEC);

		bubi_status.set_session_id(session_id_);
		bubi_status.set_system_uptime(time_stamp.ToFormatString(false));
		bubi_status.set_process_uptime(process_time_stamp.ToFormatString(false));
		bubi_status.set_system_current_time(utils::Timestamp::Now().ToFormatString(false));

		monitor::Peers *peers = bubi_status.mutable_peers();
		peers->set_peer_id(peer_node_address_);

		bubi::ConnectionMap connections = PeerManager::Instance().ConsensusNetwork().GetPeers();
		for (auto &item : connections) {
			monitor::Peer *peer = peers->add_peer();
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

	bool MonitorClient::GetLedgerStatus(int64_t seq, int32_t num, monitor::LedgerStatus &ledger_status) {
		if (!bubi::LedgerFrm::LoadFromDb(seq, num, ledger_status)) {
			return false;
		}
		return true;
	}

	bool MonitorClient::SendRequest(int64_t type, void *data) {
		bool bret = false;
		do {
			if (session_id_.empty()) break;

			std::string data_with_session_id;
			switch (type) {
			case monitor::MONITOR_MSGTYPE_BUBI: {
				monitor::BubiStatus *bubi_status = (monitor::BubiStatus *)data;
				bubi_status->set_session_id(session_id_);
				data_with_session_id = bubi_status->SerializeAsString();
				break;
			}
			case monitor::MONITOR_MSGTYPE_LEDGER: {
				monitor::LedgerStatus *ledger_status = (monitor::LedgerStatus *)data;
				ledger_status->set_session_id(session_id_);
				data_with_session_id = ledger_status->SerializeAsString();
				break;
			}
			case monitor::MONITOR_MSGTYPE_NOTICE:{
				
				break;
			}
			}

			utils::MutexGuard guard(conns_list_lock_);
			for (auto item : connections_) {
				monitor::Monitor *peer = (monitor::Monitor *)item.second;
				if (peer->IsActive() && !peer->InBound()) {
					bret = peer->SendRequest(type, data_with_session_id, last_ec_);
				}
			}
		} while (false);
		return bret;
	}

	void MonitorClient::OnTimer(int64_t current_time) {
		// reconnect if disconnect
		if (current_time - last_connect_time_ > connect_interval_) {
			if (!is_connected_ && init_) {
				std::string url = utils::String::Format("ws://%s", Configure::Instance().monitor_configure_.connect_address_.c_str());
				Connect(url);
			}
			last_connect_time_ = current_time;
		}
	}

	void MonitorClient::OnSlowTimer(int64_t current_time) {
		system_manager_.OnSlowTimer();
	}

	void MonitorClient::GetModuleStatus(Json::Value &data) {

	}

}

