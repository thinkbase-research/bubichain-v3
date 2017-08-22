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

#ifndef MONITOR_H_
#define MONITOR_H_

#include <proto/cpp/monitor.pb.h>
#include <proto/cpp/overlay.pb.h>
#include <common/network.h>

namespace monitor {
	typedef std::shared_ptr<protocol::WsMessage> WsMessagePointer;

	class Monitor : public bubi::Connection {
	private:

		bool state_changed_;
		int64_t active_time_;
		std::string session_id_;
		std::string peer_node_address_;
		//bubi пео╒
		std::string bubi_version_;
		int64_t monitor_version_;
		int64_t bubi_ledger_version_;
		std::string bubi_node_address_;

	public:
		Monitor(bubi::server *server_h, bubi::client *client_h, bubi::tls_server *tls_server_h, bubi::tls_client *tls_client_h, 
			bubi::connection_hdl con, const std::string &uri, int64_t id);

		void SetSessionId(const std::string &session_id);
		void SetActiveTime(int64_t current_time);
		bool IsActive() const;
		int64_t GetActiveTime() const;

		utils::InetAddress GetRemoteAddress() const;
		std::string GetPeerNodeAddress() const;

		bool SendHello(int32_t listen_port, const std::string &node_address, std::error_code &ec);
		void SetBubiInfo(const protocol::ChainStatus &hello);
	};
}

#endif