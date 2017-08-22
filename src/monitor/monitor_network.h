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

#ifndef MONITOR_NETWORK_H_
#define MONITOR_NETWORK_H_

#include "monitor.h"
#include "alert.h"
#include "notice.h"
#include <common/network.h>
#include <common/general.h>

namespace monitor {
	class MonitorNetwork : 
		public bubi::Network,
		public bubi::TimerNotify {
	public:
		MonitorNetwork(const bubi::SslParameter &ssl_parameter_);

		bool Initialize();
		bool Exit();

		virtual void OnTimer(int64_t current_time) override;
		virtual void OnSlowTimer(int64_t current_time) override;

	private:
		virtual void OnDisconnect(bubi::Connection *conn);
		virtual bool OnConnectOpen(bubi::Connection *conn);
		virtual bubi::Connection *CreateConnectObject(bubi::server *server_h, bubi::client *client_,
			bubi::tls_server *tls_server_h, bubi::tls_client *tls_client_h,
			bubi::connection_hdl con, const std::string &uri, int64_t id);

		// for monitor center
		bool OnMonitorRegister(protocol::WsMessage &message, int64_t conn_id);
		bool OnMonitorInfo(protocol::WsMessage &message, int64_t conn_id);

		// to bubi
		bool OnHelloStatus(protocol::WsMessage &message, int64_t conn_id);
		bool OnAlertStatus(protocol::WsMessage &message, int64_t conn_id);
		bool OnNoticeStatus(protocol::WsMessage &message, int64_t conn_id);
		
		bool NodeExist(std::string node_address, int64_t peer_id);
		bubi::Connection *GetServerConnection();
		bubi::Connection *GetClientConnection();
	private:
		std::string monitor_id_;

		bool init_;
		bool is_connected_;
		bool is_registered_;

		uint64_t check_alert_interval_;
		uint64_t last_alert_time_;

		uint64_t last_connect_time_;
		uint64_t connect_interval_;

		Alert alert_;
		Notice notice_;
	};
}

#endif