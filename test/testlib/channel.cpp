#include <utils/timestamp.h>
#include <utils/logger.h>
#include <common/general.h>
#include "channel.h"

namespace bubi1 {

	Connection::Connection(server *server_h, client *client_h, connection_hdl con, const std::string &uri, int64_t id) :
		server_(server_h),
		client_(client_h),
		connection_(con),
		in_bound_(server_h ? true : false),
		uri_(uri), 
		id_(id), 
		sequence_(0){
		connect_start_time_ = 0;
		connect_end_time_ = 0;
		last_receive_time_ = 0;
		last_send_time_ = 0;

		std::error_code ec;
		last_receive_time_ = connect_start_time_ = utils::Timestamp::HighResolution();
		if (server_){
			connect_end_time_ = connect_start_time_;

			server::connection_ptr con = server_->get_con_from_hdl(connection_, ec);
			if(!ec) peer_address_ = utils::InetAddress(con->get_remote_endpoint());
		}
		else {
			client::connection_ptr con = client_->get_con_from_hdl(connection_, ec);
			if (!ec) peer_address_ = utils::InetAddress(con->get_host(), con->get_port());
		}
	}
	Connection::~Connection() {}

	utils::InetAddress Connection::GetPeerAddress() const {
		return peer_address_;
	}

	void Connection::TouchReceiveTime() {
		last_receive_time_ = utils::Timestamp::HighResolution();
	}

	bool Connection::NeedPing(int64_t interval) {
		return utils::Timestamp::HighResolution() - last_send_time_ > interval;
	}

	void Connection::SetConnectTime() {
		connect_end_time_ = utils::Timestamp::HighResolution();
	}

	int64_t Connection::GetId() const{
		return id_;
	}

	websocketpp::lib::error_code Connection::GetErrorCode() const {
		std::error_code ec;
		if (in_bound_) {
			server::connection_ptr con = server_->get_con_from_hdl(connection_, ec);
			if (!ec) {
				ec = con->get_ec();
			}
		}
		else {
			client::connection_ptr con = client_->get_con_from_hdl(connection_, ec);
			if (!ec) {
				ec = con->get_ec();
			}
		}

		return ec;
	}

	bool Connection::SendByteMessage(const std::string &message, std::error_code &ec) {
		std::error_code ec1;
		if (in_bound_){
			server_->send(connection_, message, websocketpp::frame::opcode::BINARY, ec1);
		} else{
			client_->send(connection_, message, websocketpp::frame::opcode::BINARY, ec1);
		}

		if (ec1.value() == 0) {
			return true;
		} else{
			ec = ec1;
			return false;
		}
	}

	bool Connection::Ping(std::error_code &ec) {
		do {
			std::error_code ec1;
			if (in_bound_) {
				server::connection_ptr con = server_->get_con_from_hdl(connection_, ec1);
				if (ec1.value() != 0) break;
				con->ping(utils::Timestamp::Now().ToFormatString(true), ec);
			}
			else {
				client::connection_ptr con = client_->get_con_from_hdl(connection_, ec1);
				if (ec1.value() != 0) break;
				con->ping(utils::Timestamp::Now().ToFormatString(true), ec);
			}

			last_send_time_ = utils::Timestamp::HighResolution();
		} while (false);

		return ec.value() == 0;
	}

	bool Connection::SendMessage(int64_t type, bool request, int64_t sequence, const std::string &data, std::error_code &ec) {
		protocol::WsMessage message;
		message.set_type(type);
		message.set_request(request);
		message.set_sequence(sequence);
		message.set_data(data);
		return SendByteMessage(message.SerializeAsString(), ec);
	}

	bool Connection::SendRequest(int64_t type, const std::string &data, std::error_code &ec) {
		protocol::WsMessage message;
		message.set_type(type);
		message.set_request(true);
		message.set_sequence(sequence_++);
		message.set_data(data);
		return SendByteMessage(message.SerializeAsString(), ec);
	}

	bool Connection::IsConnectExpired(int64_t time_out) const {
		return connect_end_time_ == 0 &&
			utils::Timestamp::HighResolution() - connect_start_time_ > time_out &&
			!in_bound_;
	}

	bool Connection::IsDataExpired(int64_t time_out) const {
		return utils::Timestamp::HighResolution() - last_receive_time_ > time_out;
	}

	void Connection::ToJson(Json::Value &status) const {
		status["id"] = id_;
		status["in_bound"] = in_bound_;
		status["peer_address"] = GetPeerAddress().ToIpPort();
	}

	Network::Network() : next_id_(0), enabled_(false){
		server_.init_asio();
		server_.set_reuse_addr(true);
		// Register handler callbacks
		server_.set_open_handler(bind(&Network::OnOpen, this, _1));
		server_.set_close_handler(bind(&Network::OnClose, this, _1));
		server_.set_fail_handler(bind(&Network::OnFailed, this, _1));
		server_.set_message_handler(bind(&Network::OnMessage, this, _1, _2));
		server_.set_pong_handler(bind(&Network::OnPong, this, _1, _2));

		//client_.clear_access_channels(websocketpp::log::alevel::all);
		//client_.clear_error_channels(websocketpp::log::elevel::all);
		client_.init_asio();

		//register function
		//request_methods_[1] = std::bind(&Network::OnRequestPing, this, std::placeholders::_1, std::placeholders::_2);
		//response_methods_[1] = std::bind(&Network::OnResponsePing, this, std::placeholders::_1, std::placeholders::_2);
	}

	Network::~Network() {}

	void Network::OnOpen(connection_hdl hdl) {
		int64_t new_id = next_id_++;
		Connection *peer = CreateConnectObject(&server_, NULL, hdl, "", new_id);
		peers_.insert(std::make_pair(new_id, peer));
		peerids_.insert(std::make_pair(hdl, new_id));

		LOG_INFO("Peer accepted, ip(%s)", peer->GetPeerAddress().ToIpPort().c_str());
		//peer->Ping(ec_);
		OnConnectOpen(peer);
	}

	void Network::OnClose(connection_hdl hdl) {
		Connection *peer = GetPeer(hdl);
		if (peer) {
			LOG_INFO("Peer closed, ip(%s)", peer->GetPeerAddress().ToIpPort().c_str());
			OnDisconnect(peer);
		} 
	}

	void Network::OnMessage(connection_hdl hdl, server::message_ptr msg) {
		LOG_INFO("Recv message %s %d", 
			utils::String::BinToHexString(msg->get_payload()).c_str(), msg->get_opcode());

		do {
			protocol::WsMessage message;
			message.ParseFromString(msg->get_payload());

			Connection *conn = GetPeer(hdl);
			if (!conn) { break; }

			conn->TouchReceiveTime();
			if (message.request()){
				MessageConnPocMap::iterator iter = request_methods_.find(message.type());
				if (iter == request_methods_.end()) break;
				MessageConnPoc proc = iter->second;
				proc(message, conn);
			} else{
				MessageConnPocMap::iterator iter = response_methods_.find(message.type());
				if (iter == response_methods_.end()) break;
				MessageConnPoc proc = iter->second;
				proc(message, conn);
			}

		} while (false);
		
	}

	void Network::Run(const utils::InetAddress &ip) {
		try
		{
			if (!ip.IsNone()) {
				// listen on specified port
				server_.listen(ip.tcp_endpoint());
				// Start the server accept loop
				server_.start_accept();
			}
			enabled_ = true;

			// Start the ASIO io_service run loop
			int64_t last_check_time = 0;
			while (enabled_) {
				if (!ip.IsNone()) server_.poll();
				client_.poll();
				utils::Sleep(1);

				int64_t now = utils::Timestamp::HighResolution();
				if (now  - last_check_time > utils::MICRO_UNITS_PER_SEC) {
					
					//check ping
					for (PeerMap::iterator iter = peers_.begin();
						iter != peers_.end();
						iter++) {
						if (iter->second->NeedPing(30 * utils::MICRO_UNITS_PER_SEC)) {
							iter->second->Ping(ec_);
						}

						if (iter->second->IsDataExpired(120 * utils::MICRO_UNITS_PER_SEC)) {
							LOG_ERROR("Data Expired");
						}
					}

					last_check_time = now;
				}
			}
		}
		catch (const std::exception & e) {
			LOG_ERROR("%s", e.what());
		}

		enabled_ = false;
	}

	bool Network::Connect(const std::string &uri) {
		websocketpp::lib::error_code ec;

		client::connection_ptr con = client_.get_connection(uri, ec);

		if (ec) {
			std::cout << "> Connect initialization error: " << ec.message() << std::endl;
			return false;
		}

		int64_t new_id = next_id_++;
		Connection *peer = CreateConnectObject(NULL, &client_, con->get_handle(), uri, new_id);
		peers_.insert(std::make_pair(new_id, peer));
		peerids_.insert(std::make_pair(con->get_handle(), new_id));

		con->set_open_handler(bind(&Network::OnClientOpen, this, _1));
		con->set_close_handler(bind(&Network::OnClientClose, this, _1));
		con->set_message_handler(bind(&Network::OnMessage, this, _1, _2));
		con->set_fail_handler(bind(&Network::OnFailed, this, _1));
		con->set_pong_handler(bind(&Network::OnPong, this, _1, _2));
		
		client_.connect(con);
		return true;
	}

	Connection *Network::GetPeer(int64_t id) {
		PeerMap::iterator iter = peers_.find(id);
		if (iter != peers_.end()){
			return iter->second;
		}

		return NULL;
	}

	Connection *Network::GetPeer(connection_hdl hdl) {
		ConnectMap::iterator iter = peerids_.find(hdl);
		if (iter == peerids_.end()) {
			return NULL;
		}

		return GetPeer(iter->second);
	}

	void Network::OnClientOpen(connection_hdl hdl) {
		Connection * conn = GetPeer(hdl);
		if (conn) {
			LOG_INFO("Peer connected, ip(%s)", conn->GetPeerAddress().ToIpPort().c_str());
			conn->SetConnectTime();
			conn->Ping(ec_);
		}
	}

	void Network::OnClientClose(connection_hdl hdl) {
		Connection *peer = GetPeer(hdl);
		LOG_INFO("Peer close, ip(%s)", peer->GetPeerAddress().ToIpPort().c_str());
		if (peer){
			OnDisconnect(peer);
		} 
	}

	void Network::OnFailed(connection_hdl hdl) {
		Connection *peer = GetPeer(hdl);
		if (peer) {
			websocketpp::lib::error_code ec = peer->GetErrorCode();
			LOG_ERROR_ERRNO("Peer failed, ip(%s)",
				peer->GetPeerAddress().ToIpPort().c_str(), ec.value(), ec.message().c_str());
			OnDisconnect(peer);
		}
	}

	void Network::OnClientMessage(connection_hdl hdl, client::message_ptr msg) {
		LOG_INFO("Client recv message %s %d",
			utils::String::BinToHexString(msg->get_payload()).c_str(), msg->get_opcode());
	}

	void Network::OnPong(connection_hdl hdl, std::string payload) {
		Connection *peer = GetPeer(hdl);
		if (peer){
			peer->TouchReceiveTime();
			LOG_INFO("Recv Pong, payload(%s)", payload.c_str());
		} 
	}

	bool Network::OnRequestPing(protocol::WsMessage &message, Connection *conn) {
		LOG_INFO("On Ping Request");
		protocol::WsMessage res = message;
		res.set_request(false);
		return conn->SendByteMessage(res.SerializeAsString(), ec_);
	}

	bool Network::OnResponsePing(protocol::WsMessage &message, Connection *conn) {
		LOG_INFO("On Ping Response");
		return true;
	}

	bool Network::Ping(Connection *conn) {
		return conn->SendRequest(1, "ping", ec_);
	}

	Connection *Network::CreateConnectObject(server *server_h, client *client_, connection_hdl con, const std::string &uri, int64_t id) {
		return new Connection(server_h, client_, con, uri, id);
	}

}
