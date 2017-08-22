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

#include <proto/cpp/overlay.pb.h>
#include <common/general.h>
#include "peer.h"

namespace bubi {
	Peer::Peer(server *server_h, client *client_h, tls_server *tls_server_h, tls_client *tls_client_h, connection_hdl con, const std::string &uri, int64_t id) :
		Connection(server_h, client_h, tls_server_h, tls_client_h, con, uri, id) {
		state_changed_ = false;
		active_time_ = 0;
		delay_ = 0;
	}

	Peer::~Peer() {}

	utils::InetAddress Peer::GetRemoteAddress() const {
		utils::InetAddress address = GetPeerAddress();
		if (InBound()) {
			address.SetPort((uint16_t)peer_listen_port_);
		}
		return address;
	}

	std::string Peer::GetPeerNodeAddress() const {
		return peer_node_address_;
	}

	bool Peer::state_changed() const {
		return state_changed_;
	}

	void Peer::clean_state_changed() {
		state_changed_ = false;
	}

	int64_t Peer::GetActiveTime() const {
		return active_time_;
	}

	bool Peer::IsActive() const {
		return active_time_ > 0;
	}

	bool Peer::SendPeers(const Json::Value &db_peers, std::error_code &ec) {

		protocol::Peers peers;
		for (size_t i = 0; i < db_peers.size(); i++) {
			const Json::Value &item = db_peers[i];
			protocol::Peer *peerp = peers.add_peers();
			peerp->set_ip(item["ip"].asCString());
			peerp->set_port(item["port"].asInt());
			peerp->set_num_failures(item["num_failures"].asInt());
		}

		return SendRequest(protocol::OVERLAY_MSGTYPE_PEERS, peers.SerializeAsString(), ec);
	}

	void Peer::SetPeerInfo(const protocol::Hello &hello) {
		peer_overlay_version_ = hello.overlay_version();
		peer_ledger_version_ = hello.ledger_version();
		peer_version_ = hello.bubi_version();
		peer_listen_port_ = hello.listening_port();
		peer_node_address_ = hello.node_address();
	}

	void Peer::SetActiveTime(int64_t current_time) {
		active_time_ = current_time;
	}

	bool Peer::SendHello(int32_t listen_port, const std::string &node_address, const int64_t &network_id, const std::string &node_rand, std::error_code &ec) {
		protocol::Hello hello;

		hello.set_ledger_version(General::LEDGER_VERSION);
		hello.set_overlay_version(General::OVERLAY_VERSION);
		hello.set_listening_port(listen_port);
		hello.set_bubi_version(General::BUBI_VERSION);
		hello.set_node_address(node_address);
		hello.set_node_rand(node_rand);
		hello.set_network_id(network_id);
		return SendRequest(protocol::OVERLAY_MSGTYPE_HELLO, hello.SerializeAsString(), ec);
	}

	void Peer::ToJson(Json::Value &status) const {
		Connection::ToJson(status);

		status["node_address"] = peer_node_address_;
		status["delay"] = delay_;
		status["active"] = IsActive();
		status["ip_address"] = GetPeerAddress().ToIpPort();
	}

	int64_t Peer::GetDelay() const {
		return delay_;
	}

}