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

#ifndef WEBSOCKET_SERVER_H_
#define WEBSOCKET_SERVER_H_

#include <proto/cpp/chain.pb.h>
#include <common/network.h>
#include <monitor/system_manager.h>

namespace bubi {
	class WebSocketServer :public utils::Singleton<WebSocketServer>,
		public StatusModule,
		public TimerNotify,
		public Network,
		public utils::Runnable {
		friend class utils::Singleton<bubi::WebSocketServer>;
	public:
		WebSocketServer();
		~WebSocketServer();

		
		//virtual bool Send(const ZMQTaskType type, const std::string& buf);

		bool Initialize(WsServerConfigure & ws_server_configure);
		bool Exit();

		virtual void OnTimer(int64_t current_time) override;
		virtual void OnSlowTimer(int64_t current_time) override;

		// Handlers
		bool OnChainHello(protocol::WsMessage &message, int64_t conn_id);
		bool OnChainPeerMessage(protocol::WsMessage &message, int64_t conn_id);
		bool OnSubmitTransaction(protocol::WsMessage &message, int64_t conn_id);

		bool OnBubiStatus(protocol::WsMessage &message, int64_t conn_id);
		bool OnLedgerStatus(protocol::WsMessage &message, int64_t conn_id);
		bool OnSystemStatus(protocol::WsMessage &message, int64_t conn_id);
		bool OnAlertStatus(protocol::WsMessage &message, int64_t conn_id);

		bool SendMonitor(int64_t type, const std::string &data);
		void BroadcastMsg(int64_t type, const std::string &data);
		void BroadcastChainTxMsg(const std::string &hash, const std::string &source_address, Result result, protocol::ChainTxStatus_TxStatus status);

		bool GetBubiStatus(monitor::BubiStatus &bubi_status);
		virtual void GetModuleStatus(Json::Value &data);
	protected:
		virtual void Run(utils::Thread *thread) override;

		virtual void OnDisconnect(Connection *conn);
		virtual bool OnConnectOpen(Connection *conn);

	private:

		bool init_;
		bool is_connected_;
		utils::Thread *thread_ptr_;

		uint64_t last_connect_time_;
		uint64_t connect_interval_;

		SystemManager system_manager_;
	};
}

#endif