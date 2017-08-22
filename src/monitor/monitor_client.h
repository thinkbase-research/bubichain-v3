#pragma once
#ifndef MONITOR_CLIENT_H_
#define MONITOR_CLIENT_H_

#include "system_manager.h"
#include <common/network.h>
#include <utils/singleton.h>
#include <common/general.h>

namespace bubi {
	class MonitorClient : 
		public utils::Singleton<MonitorClient>,
		public Network,
		public TimerNotify,
		public utils::Runnable {
		friend class utils::Singleton<MonitorClient>;
	public:
		MonitorClient();
		~MonitorClient();

		bool Initialize();
		bool Exit();

		virtual void OnTimer(int64_t current_time) override;
		virtual void OnSlowTimer(int64_t current_time) override;

		virtual void GetModuleStatus(Json::Value &data);

		virtual void OnDisconnect(Connection *conn);
		virtual bool OnConnectOpen(Connection *conn);
		virtual Connection *CreateConnectObject(server *server_h, client *client_,
			tls_server *tls_server_h, tls_client *tls_client_h,
			connection_hdl con, const std::string &uri, int64_t id);

		bool GetBubiStatus(monitor::BubiStatus &bubi_status);
		bool GetLedgerStatus(int64_t seq, int32_t num, monitor::LedgerStatus &ledger_status);

		bool SendRequest(int64_t type, void *data);

	protected:
		virtual void Run(utils::Thread *thread) override;

	private:
		bool OnMethodBubi(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodLedger(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodSystem(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodAlert(protocol::WsMessage &message, int64_t conn_id);

	private:
		utils::Thread *thread_ptr_;
		std::string peer_node_address_;
		std::string session_id_;
		std::error_code last_ec_;

		bool init_;
		bool is_connected_;

		uint64_t last_connect_time_;
		uint64_t connect_interval_;

		// system
		SystemManager system_manager_;
	};
}

#endif