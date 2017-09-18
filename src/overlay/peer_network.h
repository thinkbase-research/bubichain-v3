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

#ifndef PEER_NETWORK_H_
#define PEER_NETWORK_H_

#include <utils/singleton.h>
#include <utils/net.h>
#include <common/general.h>
#include <common/private_key.h>
#include <common/network.h>
#include "peer.h"
#include "broadcast.h"

namespace bubi {

	class PeerNetwork :
		public Network,
		public TimerNotify,
		public IBroadcastDriver {
	public:
		PeerNetwork(const SslParameter &ssl_parameter_);
		~PeerNetwork();

	private:
		asio::ssl::context context_;

		bool dns_seed_inited_;
		bool cert_is_valid_;

		//Peer cach list
		Json::Value db_peer_cache_;

		//peers infomation received
		utils::Mutex peer_lock_;
		std::list<utils::StringMap> received_peer_list_;

		Broadcast broadcast_;

		// cert is enable or unable
		bool cert_enabled_;

		std::string peer_node_address_;
		std::string node_rand_;
		int64_t network_id_;

		std::error_code last_ec_;

		void Clean();

 		bool ResolveSeeds(const utils::StringList &address_list, int32_t rank);
		bool ConnectToPeers(size_t max);
		bool LoadSeed();
		bool LoadHardcode();

		bool ResetPeerInActive();
		bool CreatePeerIfNotExist(const utils::InetAddress &address);
		bool GetActivePeers(int32_t max);

		bool OnMethodHello(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodPeers(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodTransaction(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodGetLedgers(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodLedgers(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodPbft(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodLedgerUpNotify(protocol::WsMessage &message, int64_t conn_id);
		bool OnMethodHelloResponse(protocol::WsMessage &message, int64_t conn_id);

		//Operate the ip list
		int32_t QueryItem(const utils::InetAddress &address, protocol::Peers &records);
		bool UpdateItem(const utils::InetAddress &address, protocol::Peer &record);
		int32_t QueryTopItem(bool active, int64_t limit, int64_t next_attempt_time, protocol::Peers &records);

		virtual void OnDisconnect(Connection *conn);
		virtual bool OnConnectOpen(Connection *conn);
		virtual Connection *CreateConnectObject(server *server_h, client *client_,
			tls_server *tls_server_h, tls_client *tls_client_h,
			connection_hdl con, const std::string &uri, int64_t id);
		virtual bool OnVerifyCallback(bool preverified, asio::ssl::verify_context& ctx);
		virtual bool OnValidate(websocketpp::connection_hdl hdl);

	public:
		bool Initialize(const std::string &node_address);
		bool Exit();

		Json::Value GetPeersCache();
		void AddReceivedPeers(const utils::StringMap &item);
		void BroadcastMsg(int64_t type, const std::string &data);
		bool ReceiveBroadcastMsg(int64_t type, const std::string &data, int64_t peer_id);

		void GetPeers(Json::Value &peers);

		virtual void OnTimer(int64_t current_time) override;
		virtual void OnSlowTimer(int64_t current_time) override {};
		void GetModuleStatus(Json::Value &data);

		virtual bool SendMsgToPeer(int64_t peer_id, WsMessagePointer msg);
		virtual bool SendRequest(int64_t peer_id, int64_t type, const std::string &data);
		virtual std::set<int64_t> GetActivePeerIds();

		bool NodeExist(std::string node_address, int64_t peer_id);
	};
}

#endif