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

#ifndef PEER_H_
#define PEER_H_

#include <proto/cpp/overlay.pb.h>
#include <common/network.h>

namespace bubi {
	typedef std::shared_ptr<protocol::WsMessage> WsMessagePointer;

	// provide p2p network interface
	class IPeerManagerNotify {
	public:
		IPeerManagerNotify();
		~IPeerManagerNotify();

		virtual void OnNetworkPrepared() = 0;
		virtual void OnMessage() = 0;
	};

	typedef std::list<IPeerManagerNotify *> PeerManagerNotifier;

	class Peer : public Connection {
	private:

		bool state_changed_;
		int64_t active_time_;
		int64_t delay_;

		//Peer infomation
		std::string peer_version_;
		int64_t peer_ledger_version_;
		int64_t peer_overlay_version_;
		int64_t peer_listen_port_;
		std::string peer_node_address_;
	public:
		Peer(server *server_h, client *client_h, tls_server *tls_server_h, tls_client *tls_client_h, connection_hdl con, const std::string &uri, int64_t id);
		virtual ~Peer();

		
		utils::InetAddress GetRemoteAddress() const;
		bool IsActive() const;
		std::string GetPeerNodeAddress() const;
		bool state_changed() const;
		void clean_state_changed();
		int64_t GetActiveTime() const;
		int64_t GetDelay() const;

		bool SendPeers(const Json::Value &db_peers, std::error_code &ec);
		void SetPeerInfo(const protocol::Hello &hello);
		void SetActiveTime(int64_t current_time);
		bool SendHello(int32_t listen_port, const std::string &node_address, const int64_t &network_id, const std::string &node_rand, std::error_code &ec);

		virtual void ToJson(Json::Value &status) const;
	};
}

#endif
