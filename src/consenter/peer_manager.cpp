#include <utils/logger.h>
#include <utils/timestamp.h>
#include <common/general.h>
#include <common/storage.h>
#include <common/configure.h>
#include <common/private_key.h>
#include <common/ca_manager.h>
#include <consensus/consensus_manager.h>
#include <proto/message.pb.h>
#include "consenter.pb.h"
#include "peer_manager.h"
#include "consenter_manager.h"

namespace bubi{

	std::shared_ptr<PeerMessage> PeerMessageWithLite::NewTransactionLite(){
		std::shared_ptr<PeerMessage>  msg = std::shared_ptr<PeerMessage>(new PeerMessageWithLite());
		memset(&msg->header_, 0, sizeof(PeerMsgHearder));
		msg->header_.type = PEER_MESSAGE_TRANSACTIONLITE;
		msg->data_ = new protocol::TransactionLite();
		return msg;
	}

	PeerMessageWithLite::PeerMessageWithLite(){}
	PeerMessageWithLite::~PeerMessageWithLite(){}

	bool PeerMessageWithLite::FromStringOther(uint16_t type, const char* data, size_t len){
		if (type == PEER_MESSAGE_TRANSACTIONLITE){
			data_ = new protocol::TransactionLite();
			data_->ParseFromArray(data, header_.data_len);
			return true;
		}

		return false;
	}

	PeerNetwork::PeerNetwork(NetworkType type)
		:type_(type),
		context_(asio::ssl::context::tlsv12),
		cert_enabled_(false),
		broadcast_(this)
	{
		async_io_ptr_ = NULL;
		acceptor_ptr_ = NULL;
		check_interval_ = 2 * utils::MICRO_UNITS_PER_SEC;
		dns_seed_inited_ = false;
		incoming_peer_ = NULL;
		timer_name_ = utils::String::Format("%s Network", type == CONSENSUS ? "Consensus" : "Transaction");
	}

	PeerNetwork::~PeerNetwork(){
		//assert(async_io_ptr_ == NULL);
		//assert(acceptor_ptr_ == NULL);
	}


	void PeerNetwork::Clean(){

	}

	bool PeerNetwork::Initialize(bool cert_enabled){
		do {
			cert_enabled_ = cert_enabled;
			async_io_ptr_ = new utils::AsyncIo();
			async_io_ptr_->AttachServiceIo(&PeerManager::Instance().GetIOService());

			if (cert_enabled_) {
				SSLConfigure& ssl_configure = Configure::Instance().p2p_configure_.ssl_configure_;
				std::string strHome = utils::File::GetBinHome();
				context_.set_options(
					asio::ssl::context::default_workarounds
					| asio::ssl::context::no_sslv2
					| asio::ssl::context::no_sslv3
					| asio::ssl::context::no_tlsv1
					| asio::ssl::context::no_tlsv1_1
					| asio::ssl::context::single_dh_use);
				context_.set_password_callback(std::bind(&PeerNetwork::GetCertPassword, this, std::placeholders::_1, std::placeholders::_2));
				context_.use_certificate_chain_file(utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.chain_file_.c_str()));
				asio::error_code ignore_code;
				context_.use_private_key_file(utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.private_key_file_.c_str()),
					asio::ssl::context::pem,
					ignore_code);
				context_.use_tmp_dh_file(utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.dhparam_file_.c_str()));
				context_.load_verify_file(utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.verify_file_.c_str()));
			}
			

			if (!CheckStorage()){
				break;
			}

			if (!Listen()){
				break;
			}

			TimerNotify::RegisterModule(this);

			last_upgrad_request_time_ = last_heartbeart_time_ = utils::Timestamp::HighResolution();
			validator_address_ = "";
			ledger_version_ = 0;


			return ResetPeerInActive();
		} while ( false );

		Clean();
		return false;
	}

	bool PeerNetwork::Exit(){
		LOG_INFO("closing acceptor...");
		if (acceptor_ptr_->Close()) {
			LOG_INFO("close acceptor OK");
		}
		delete acceptor_ptr_;
		acceptor_ptr_ = NULL;

		for (auto item : peer_list_) {
			delete item.second;
		}

		for (auto item : peer_list_delete_){
			delete item.second;
		}

		if (incoming_peer_){
			delete incoming_peer_;
		}
		LOG_INFO("closing async...");
		if (async_io_ptr_->Close()) {
			LOG_INFO("close async OK");
		}
		delete async_io_ptr_;
		async_io_ptr_ = NULL;

		return true;
	}

    void PeerManager::Run(utils::Thread *thread)
	{
        asio::io_service::work work(asio_service_);

		while (!asio_service_.stopped()){
			asio::error_code err;
			asio_service_.poll(err);

			utils::Sleep(1);
		}
	}

	std::string PeerNetwork::GetCertPassword(std::size_t, asio::ssl::context_base::password_purpose purpose) {
		return "bubi";
	}

	void PeerNetwork::OnAccept(utils::AsyncSocketAcceptor *acceptor_ptr){
		OnStartReceive();
	}

	void PeerNetwork::OnStartReceive() {
		//新连接已经过来，接下来入库保存，并开始peer 协议的开始
		const P2pNetwork &p2p_configure =
			type_ == CONSENSUS
			? Configure::Instance().p2p_configure_.consensus_network_configure_
			: Configure::Instance().p2p_configure_.transaction_network_configure_;

		if (peer_list_.size() < p2p_configure.target_peer_connection_){
			do {
				utils::MutexGuard guard(peer_list_mutex_);
				incoming_peer_->OnAcceptedPeer();
				peer_list_.insert(std::make_pair(incoming_peer_->peer_id(), incoming_peer_));
			} while (false);
		}
		else
		{
			//超出则拒绝连接。
			//incoming_peer_->Close();
			delete incoming_peer_;
		}

		//继续监听新连接
		if (cert_enabled_){
			incoming_peer_ = new SslPeer(async_io_ptr_, this, PeerManager::GetInstance(), context_, true);
			acceptor_ptr_->AsyncAccept((SslPeer *)incoming_peer_);
		}
		else{
			incoming_peer_ = new TcpPeer(async_io_ptr_, this, PeerManager::GetInstance(), true);
			acceptor_ptr_->AsyncAccept((TcpPeer *)incoming_peer_);
		}
	}

	void PeerNetwork::OnError(utils::AsyncSocketAcceptor *acceptor_ptr){
		LOG_ERROR_ERRNO("Accept incoming failed", STD_ERR_CODE, STD_ERR_DESC);
	}

	bool PeerNetwork::Listen(){
		const P2pNetwork &p2p_configure =
			type_ == CONSENSUS
			? Configure::Instance().p2p_configure_.consensus_network_configure_
			: Configure::Instance().p2p_configure_.transaction_network_configure_;
		do
		{
			acceptor_ptr_ = new utils::AsyncSocketAcceptor(async_io_ptr_, this);
			utils::InetAddress listen_address_ = utils::InetAddress::Any();
			listen_address_.SetPort(p2p_configure.listen_port_);
			if (!acceptor_ptr_->Bind(listen_address_)){
				LOG_ERROR_ERRNO("Peer acceptor bind address(%s) failed", listen_address_.ToIpPort().c_str(), STD_ERR_CODE, STD_ERR_DESC);
				break;
			}

			if (!acceptor_ptr_->Listen()){
				LOG_ERROR_ERRNO("Peer acceptor listen address(%s) failed", listen_address_.ToIpPort().c_str(), STD_ERR_CODE, STD_ERR_DESC);
				break;
			}

			LOG_INFO("Peer listen on address(%s) successful", listen_address_.ToIpPort().c_str());

			if (cert_enabled_){
				incoming_peer_ = new SslPeer(async_io_ptr_, this, PeerManager::GetInstance(), context_, true);
				acceptor_ptr_->AsyncAccept((SslPeer *)incoming_peer_);
			}
			else{
				incoming_peer_ = new TcpPeer(async_io_ptr_, this, PeerManager::GetInstance(), true);
				acceptor_ptr_->AsyncAccept((TcpPeer *)incoming_peer_);
			}

			return true;
		} while (false);

		return false;
	}

	bool PeerNetwork::CheckStorage(){
		//判断数据库中是否已有 Peers 表，如果没有则创建
		Json::Value table_desc = Json::Value(Json::arrayValue);
		RationalDb *db = Storage::Instance().rational_db();
		do {
			Json::Value columns = Json::Value(Json::arrayValue);
			int32_t ret = db->DescribeTable(General::PEERS_TABLE_NAME[type_], columns);
			if (ret < 0){
				LOG_ERROR_ERRNO("Describe table(%s) failed", General::PEERS_TABLE_NAME[type_], db->error_code(), db->error_desc());
				break;
			}

			if (ret > 0){
				return true;
			}

			if (!db->Execute(General::PEERS_CREATE_SQL[type_])){
				LOG_ERROR_ERRNO("Create table(%s) failed", General::PEERS_TABLE_NAME[type_], db->error_code(), db->error_desc());
				break;
			}

			return true;
		} while (false);

		return false;
	}

	bool PeerNetwork::ConnectToPeers(size_t max){
		const P2pNetwork &p2p_configure =
			type_ == CONSENSUS
			? Configure::Instance().p2p_configure_.consensus_network_configure_
			: Configure::Instance().p2p_configure_.transaction_network_configure_;

		RationalDb *db = Storage::Instance().rational_db();
		std::string sql = utils::String::Format("SELECT * FROM %s WHERE next_attempt_time < " FMT_I64
			" AND active_time <= 0 ORDER BY rank DESC, num_failures ASC LIMIT " FMT_SIZE, General::PEERS_TABLE_NAME[type_], utils::Timestamp::Now().timestamp(), max);
		Json::Value records = Json::Value(Json::arrayValue);
		do {
			int32_t row_count = db->Query(sql, records);
			if (row_count < 0){
				LOG_ERROR_ERRNO("Query records with sql(%s) failed", sql.c_str(), db->error_code(), db->error_desc());
				break;
			}

			utils::InetAddressVec addresses;
			utils::net::GetNetworkAddress(addresses);

			utils::MutexGuard guard(peer_list_mutex_);

			for (size_t i = 0; i < records.size();i++){
				const Json::Value &item = records[i];
				utils::InetAddress address(item["ip"].asString(), item["port"].asUInt());
				int32_t num_failures = item["num_failures"].asInt();

				LOG_DEBUG("checking address %s,"FMT_SIZE, address.ToIpPort().c_str(), utils::Thread::current_thread_id());

				//判断 IP 是否已经存在
				bool exist = false;
				for (PeerMap::iterator iter = peer_list_.begin(); iter != peer_list_.end(); iter++ )
				{
					if (iter->second->GetRemoteAddress() == address){
						exist = true;
						break;
					}
				}

				if (exist){
					LOG_DEBUG("skip to connect exist %s, " FMT_SIZE, address.ToIpPort().c_str(), utils::Thread::current_thread_id());
					continue;
				}
				bool is_local_addr = false;
				for (utils::InetAddressVec::iterator iter = addresses.begin();
					iter != addresses.end();
					iter++){
					if (iter->ToIp() == address.ToIp() && p2p_configure.listen_port_ == address.GetPort()){
						is_local_addr = true;
						break;
					}
				}

				if (is_local_addr)
				{
					LOG_TRACE("skip to connect self %s, " FMT_SIZE, address.ToIpPort().c_str(), utils::Thread::current_thread_id());
					continue;
				}


				LOG_TRACE("connect to %s, " FMT_SIZE, address.ToIpPort().c_str(), utils::Thread::current_thread_id());

				Peer *outbound_peer = NULL;
				if (cert_enabled_){
					outbound_peer = new SslPeer(async_io_ptr_, this, PeerManager::GetInstance(), context_, false);
				}
				else{
					outbound_peer = new TcpPeer(async_io_ptr_, this, PeerManager::GetInstance(), false);
				}

				peer_list_.insert(std::make_pair(outbound_peer->peer_id(), outbound_peer));
				outbound_peer->ConnectPeer(address);

				utils::StringMap update_values;
				num_failures++;
				update_values["next_attempt_time"] = utils::String::ToString(int64_t(utils::Timestamp::Now().timestamp() + num_failures * 10 * utils::MICRO_UNITS_PER_SEC));
				update_values["num_failures"] = utils::String::ToString(num_failures);
				if (!UpdatePeer(address, update_values)){
					LOG_ERROR_ERRNO("Update peers failed", db->error_code(), db->error_desc());
				}

				//PEER 列表已经达到目标上限，暂停尝试新Peer连接
				if (peer_list_.size() >= p2p_configure.target_peer_connection_){
					break;
				}
			}

			return true;
		} while (false);

		return false;
	}

	bool PeerNetwork::ResolveSeeds(const utils::StringList &address_list, int32_t rank){
		utils::NameResolver resolver(async_io_ptr_);
		for (utils::StringList::const_iterator iter = address_list.begin();
			iter != address_list.end();
			iter++){
			const std::string &longip = *iter;
			utils::StringVector ip_array = utils::String::Strtok(longip, ':');
			std::string ip = longip;
			uint16_t port = type_ == CONSENSUS ? General::CONSENSUS_PORT : General::TRANSACTION_PORT;
			if (ip_array.size() > 1){
				port = utils::String::Stoui(ip_array[1]);
				ip = ip_array[0];
			}
			else{
				continue;
			}

			utils::InetAddressList resolved_ips;
			do {
				utils::InetAddress address(ip);
				if (!address.IsNone()){
					resolved_ips.push_back(address);
					break;
				}
				//go to resolve
				resolver.Query(ip, resolved_ips);
			} while (false);

			for (utils::InetAddressList::iterator iter = resolved_ips.begin();
				iter != resolved_ips.end();
				iter++){

				utils::InetAddress &address = *iter;
				address.SetPort(port);

				CreatePeerIfNotExist(address, rank);
			}

		}
		return true;
	}

	bool PeerNetwork::CreatePeerIfNotExist(const utils::InetAddress &address, int32_t rank){
		RationalDb *db = Storage::Instance().rational_db();
		std::string sql_where = utils::String::Format("WHERE ip='%s' AND port=%u", address.ToIp().c_str(), address.GetPort());
		int64_t peer_count = db->QueryCount(General::PEERS_TABLE_NAME[type_], sql_where);
		if (peer_count < 0){
			LOG_ERROR_ERRNO("Query peer if exist failed,sql(%s)", sql_where.c_str(), db->error_code(), db->error_desc());
			return false;
		}

		if (peer_count > 0){
			LOG_TRACE("Query peer(%s) exist", address.ToIpPort().c_str());
			return true;
		}

		utils::StringMap values;
		values["ip"] = address.ToIp();
		values["port"] = utils::String::ToString(address.GetPort());
		values["rank"] = utils::String::ToString(rank);
		values["num_failures"] = "0";
		values["next_attempt_time"] = "0";
		values["active_time"] = "0";

		if (!db->Insert(General::PEERS_TABLE_NAME[type_], values)) {
			LOG_ERROR_ERRNO("Insert peer failed", db->error_code(), db->error_desc());
			return false;
		}

		return true;
	}

	bool PeerNetwork::ResetPeerInActive(){
		RationalDb *db = Storage::Instance().rational_db();
		utils::StringMap values;
		values["active_time"] = "0";
		return db->Update(General::PEERS_TABLE_NAME[type_], values, "");
	}

	bool PeerNetwork::UpdatePeer(const utils::InetAddress &local_address, const utils::StringMap &values){
		RationalDb *db = Storage::Instance().rational_db();
		std::string sql_where = utils::String::Format("WHERE ip='%s' AND port=%u", local_address.ToIp().c_str(), local_address.GetPort());
		return db->Update(General::PEERS_TABLE_NAME[type_], values, sql_where);
	}

	bool PeerNetwork::GetActivePeers(int32_t max){
		const P2pNetwork &p2p_configure =
			type_ == CONSENSUS
			? Configure::Instance().p2p_configure_.consensus_network_configure_
			: Configure::Instance().p2p_configure_.transaction_network_configure_;
		RationalDb *db = Storage::Instance().rational_db();
		std::string sql = utils::String::Format("SELECT * FROM %s "
			" ORDER BY active_time DESC, num_failures ASC LIMIT %d", General::PEERS_TABLE_NAME[type_], max);
		do {
			db_peer_cache_.clear();
			int32_t row_count = db->Query(sql, db_peer_cache_);
			if (row_count < 0){
				LOG_ERROR_ERRNO("Query records with sql(%s) failed", sql.c_str(), db->error_code(), db->error_desc());
				break;
			}

			return true;
		} while (false);
		return false;
	}

	void PeerNetwork::GetPeers(Json::Value &peers){
		utils::MutexGuard guard(peer_list_mutex_);
		for (auto item : peer_list_){
			item.second->ToJson(peers[peers.size()]);
		}
	}

	void PeerNetwork::OnTimer(int64_t current_time){
		const P2pNetwork &p2p_configure =
			type_ == CONSENSUS
			? Configure::Instance().p2p_configure_.consensus_network_configure_
			: Configure::Instance().p2p_configure_.transaction_network_configure_;
		if (!dns_seed_inited_){
			ResolveSeeds(p2p_configure.known_peer_list_, 2);
			dns_seed_inited_ = true;
			return;
		}

		//start to connect peers
		if (peer_list_.size() < p2p_configure.target_peer_connection_){
			ConnectToPeers(p2p_configure.target_peer_connection_ - peer_list_.size());
		}

		do {
			utils::MutexGuard guard(peer_list_mutex_);
			for (PeerMap::iterator iter = peer_list_.begin();
				iter != peer_list_.end();
				){
				Peer *peer = iter->second;
				if (peer->IsConnectExpired(p2p_configure.connect_timeout_)){

					//Expired
					peer->ClosePeer();
					peer_list_.erase(iter++);
					peer_list_delete_.insert(std::make_pair(utils::Timestamp::HighResolution() + 5 * utils::MICRO_UNITS_PER_SEC, peer));
				}
				else if (peer->IsActive() && peer->state_changed()){
					//connect has been established, update db data
					if (peer->in_bound()){
						//create
						CreatePeerIfNotExist(peer->GetRemoteAddress(), 1);

						//send local peer list
						GetActivePeers(50);
						peer->SendPeers(db_peer_cache_);
					}

					//update status
					utils::StringMap values;
					values["num_failures"] = "0";
					values["active_time"] = utils::String::ToString(peer->active_time());
					UpdatePeer(peer->GetRemoteAddress(), values);
					peer->clean_state_changed();

					iter++;
				}
				else if (!peer->IsActive() && peer->state_changed()){
					utils::StringMap values;
					values["active_time"] = "0";
					UpdatePeer(peer->GetRemoteAddress(), values);
					peer->clean_state_changed();

					peer->ClosePeer();
					peer_list_.erase(iter++);
					peer_list_delete_.insert(std::make_pair(utils::Timestamp::HighResolution() + 5 * utils::MICRO_UNITS_PER_SEC, peer));
				}
				else if (peer->IsDataExpired(p2p_configure.heartbeat_interval_ * 3)){
					utils::StringMap values;
					values["active_time"] = "0";
					UpdatePeer(peer->GetRemoteAddress(), values);
					peer->clean_state_changed();

					peer->ClosePeer();
					peer_list_.erase(iter++);
					peer_list_delete_.insert(std::make_pair(utils::Timestamp::HighResolution() + 5 * utils::MICRO_UNITS_PER_SEC, peer));
				}
				else{
					iter++;
				}
			}
		} while (false);

		int64_t high_resolution_time = utils::Timestamp::HighResolution();
		if (high_resolution_time - last_heartbeart_time_ > p2p_configure.heartbeat_interval_){
			utils::MutexGuard guard(peer_list_mutex_);
			for (PeerMap::iterator iter = peer_list_.begin();
				iter != peer_list_.end();
				iter++
				){
				if (iter->second->IsActive()){
					iter->second->SendPing();
				}
			}
			last_heartbeart_time_ = high_resolution_time;
		}

		//check the peer to be delete
		for (auto iter = peer_list_delete_.begin();
			iter != peer_list_delete_.end();){
			if (iter->first < utils::Timestamp::HighResolution()){
				delete iter->second;
				peer_list_delete_.erase(iter++);
			}
			else{
				break;
			}
		}

		//process the peers that have been received
		std::list<utils::StringMap> received_list;
		if (received_peer_list_.size() > 0){
			utils::MutexGuard guard(peer_list_mutex_);
			received_list = received_peer_list_;
			received_peer_list_.clear();
		}
		for (std::list<utils::StringMap>::iterator iter = received_list.begin();
			iter != received_list.end();
			iter++){
			utils::StringMap item = *iter;
			std::string ip = item["ip"];
			uint16_t port = utils::String::Stoui(item["port"]);

			//check if it's local address
			utils::InetAddressVec addresses;
			bool is_local_addr = false;
			if (utils::net::GetNetworkAddress(addresses)){
				for (utils::InetAddressVec::iterator iter = addresses.begin();
					iter != addresses.end();
					iter++){
					if (iter->ToIp() == ip && p2p_configure.listen_port_ == port){
						is_local_addr = true;
						break;
					}
				}
			}

			if (is_local_addr){
				continue;
			}

			CreatePeerIfNotExist(utils::InetAddress(ip, port), 1);
		}
		broadcast_.OnTimer();
	}

	Json::Value PeerNetwork::GetPeersCache(){
		return db_peer_cache_;
	}

	void PeerNetwork::AddReceivedPeers(const utils::StringMap &item){
		utils::MutexGuard guard(peer_list_mutex_);
		received_peer_list_.push_back(item);
	}

	void PeerNetwork::Broadcast(const PeerMessagePointer &message){
		broadcast_.Send(message);
	}

	bool PeerNetwork::ReceiveBroadcastMsg(const PeerMessagePointer &message, int64_t peer_id){
		return broadcast_.Add(message, peer_id);
	}

	bool PeerNetwork::SendMessage(int64_t peer_id, PeerMessagePointer message){
		utils::MutexGuard guard(peer_list_mutex_);
		PeerMap::iterator iter = peer_list_.find(peer_id);
		if (iter != peer_list_.end() && iter->second->IsActive()){
			return iter->second->SendMessage(message->ToString());
		}

		return false;
	}

	std::set<int64_t> PeerNetwork::GetActivePeerIds(){
		std::set<int64_t> ids;
		utils::MutexGuard guard(peer_list_mutex_);
		for (auto item : peer_list_){
			if (item.second->IsActive()){
				ids.insert(item.second->peer_id());
			}
		}

		return ids;
	}

	bool PeerNetwork::NodeExist(std::string node_address, int64_t peer_id)
	{
		bool exist = false;
		for (PeerMap::iterator iter = peer_list_.begin(); iter != peer_list_.end(); iter++)
		{
			if (iter->second->peer_node_address() == node_address && iter->second->peer_id() != peer_id){
				exist = true;
				break;
			}
		}
		return exist;
	}

	void PeerNetwork::GetModuleStatus(Json::Value &data) {
		utils::MutexGuard guard(peer_list_mutex_);
		data["peer_list_size"] = peer_list_.size();
		data["peer_listdel_size"] = peer_list_delete_.size();
		data["peer_cache_size"] = db_peer_cache_.size();
		data["recv_peerlist_size"] = received_peer_list_.size();
		data["broad_reocrd_size"] = broadcast_.GetRecordSize();
		data["notify_size"] = notifiers_.size();
		int active_size = 0;
		Json::Value peers;

		size_t send_buffer_listsize = 0;
		size_t send_buffer_size = 0;
		size_t recv_buffer_size = 0;
		for (auto &item : peer_list_){
			send_buffer_listsize += item.second->GetSendBufferListSize();
			send_buffer_size += item.second->GetSendBufferSize();
			recv_buffer_size += item.second->GetRecvBufferSize();

			Json::Value peer;
			peer["id"] = Json::Value(item.second->peer_node_address());
			peer["delay"] = Json::Value(item.second->delay());
			peers.append(peer);

			if (item.second->IsActive()) {
				active_size++;
			}
		}
		data["peers"] = peers;
		data["sendbuf_list_size"] = send_buffer_listsize;
		data["sendbuf_size"] = send_buffer_size;
		data["recvbuf_size"] = recv_buffer_size;
		data["active_size"] = active_size;
	}


	PeerManager::PeerManager()
	:consensus_network_(PeerNetwork::CONSENSUS),
    peer_methods_(),
    asio_service_(),
    thread_ptr_(NULL),
	priv_key_(ED25519SIG)
	{
		peer_methods_[PeerMessage::PEER_MESSAGE_PBFT] = std::bind(&PeerManager::OnPbft, this, std::placeholders::_1, std::placeholders::_2);
		peer_methods_[PeerMessage::PEER_MESSAGE_PEERS] = std::bind(&PeerManager::OnPeers, this, std::placeholders::_1, std::placeholders::_2);
		peer_methods_[PeerMessage::PEER_MESSAGE_GETPEERS] = std::bind(&PeerManager::OnGetPeers, this, std::placeholders::_1, std::placeholders::_2);
		peer_methods_[PeerMessage::PEER_MESSAGE_HELLO] = std::bind(&PeerManager::OnHello, this, std::placeholders::_1, std::placeholders::_2);
		peer_methods_[PeerMessage::PEER_MESSAGE_DONTHAVE] = std::bind(&PeerManager::OnDontHave, this, std::placeholders::_1, std::placeholders::_2);
		peer_methods_[PeerMessage::PEER_MESSAGE_PING] = std::bind(&PeerManager::OnPing, this, std::placeholders::_1, std::placeholders::_2);
		peer_methods_[PeerMessage::PEER_MESSAGE_PONG] = std::bind(&PeerManager::OnPong, this, std::placeholders::_1, std::placeholders::_2);
		peer_methods_[PeerMessageWithLite::PEER_MESSAGE_TRANSACTIONLITE] = std::bind(&PeerManager::OnTransactionLite, this, std::placeholders::_1, std::placeholders::_2);
	}
	PeerManager::~PeerManager()
    {
        if (thread_ptr_)
        {
            delete thread_ptr_;
        }
	}

	bool PeerManager::OnAppMsgNotify(const PeerMessagePointer &message, Peer *peer){
		MessagePeerPocMap::iterator iter = peer_methods_.find(message->header_.type);
		if (iter != peer_methods_.end()){
			MessagePeerPoc proc = iter->second;
			return proc(message, peer);
		}
		return false;
	}

	int32_t PeerManager::OnTransactionNotify(const PeerMessagePointer &message, const std::string &buffer, Peer *peer){
		if (!consensus_network_.ReceiveBroadcastMsg(message, peer->peer_id()))
		{
			return -1;
		}

		return 0;
	}
    
	bool PeerManager::Initialize(char *serial_num, bool cert_enabled)
	{
		serial_num_ = serial_num;
		cert_enabled_ = cert_enabled;
		if (!consensus_network_.Initialize() ) {
            return false;
		}

		KeyValueDb *db = Storage::Instance().keyvalue_db();
		std::string key = utils::String::Format("%s_nodeprivkey", General::OVERLAY_PREFIX);
		std::string name;
		if (db->Get(key, name) && priv_key_.From(name)){
			peer_node_address_ = priv_key_.GetBase16Address();
		}
		else{
			peer_node_address_ = priv_key_.GetBase16Address();
			db->Put(key, priv_key_.GetBase58PrivateKey());
		}

        thread_ptr_ = new utils::Thread(this);
        if (!thread_ptr_->Start("peer-manager"))
        {
            return false;
        }

		StatusModule::RegisterModule(this);
		TimerNotify::RegisterModule(this);

		return true;
	}

	bool PeerManager::Exit(){
		asio_service_.stop();
		bool ret3 = thread_ptr_->JoinWithStop();
		bool ret2 = consensus_network_.Exit();
		return ret2 && ret3 ;
	}


	void PeerManager::Broadcast(const PeerMessagePointer &message){
		switch (message->header_.type)
		{
		case PeerMessageWithLite::PEER_MESSAGE_TRANSACTIONLITE:
		default:
			consensus_network_.Broadcast(message);
			break;
		}
	}


	bool PeerManager::SendMessage(int64_t peer_id, PeerMessagePointer &message){
		bool ret = false;
		switch (message->header_.type)
		{
		case PeerMessageWithLite::PEER_MESSAGE_TRANSACTIONLITE:
		default:
			ret = consensus_network_.SendMessage(peer_id, message);
			break;
		}

		return ret;
	}


	bool PeerManager::OnPbft(const PeerMessagePointer &message, Peer *peer){
		peer->GetPeerNetwork()->ReceiveBroadcastMsg(message, peer->peer_id());
		const protocol::PbftEnv *env = (const protocol::PbftEnv *)message->data_;
		if (!env->IsInitialized()){
			LOG_ERROR("Pbft env is not initialize");
		}

		ConsensusMsg msg(*env);
		std::string hash = utils::String::Bin4ToHexString(HashWrapper::Crypto(message->GetString()));
		LOG_INFO("[" FMT_I64 "]On pbft hash(%s), receive consensus from node address(%s) sequence(" FMT_I64 ") pbft type(%s)",
            peer->peer_id(), hash.c_str(), msg.GetNodeAddress(), msg.GetSeq(),
			PbftDesc::GetMessageTypeDesc(msg.GetPbft().pbft().type()));
		ConsenterManager::Instance().OnConsensus(msg);
//		if (!GlueManager::Instance().ConsensusHasRecv(msg)){
//			LOG_INFO("Pbft hash(%s) would be processed", hash.c_str());
//			GlueManager::Instance().RecvConsensus(msg);
//		}

		return true;
	}

	bool PeerManager::OnPeers(const PeerMessagePointer &message, Peer *peer){
		utils::StringMap values;
		const protocol::Peers *peers = (const protocol::Peers *)message->data_;
		for (int i = 0; i < peers->peers_size(); i++){
			const protocol::Peer &peerp = peers->peers(i);
			values["ip"] = peerp.ip();
			values["port"] = utils::String::ToString(peerp.port());
			values["num_failures"] = utils::String::ToString(peerp.num_failures());
			//LOG_INFO("%s add peers %s:%d", 
			//	peer->GetPeerNetwork()->GetNetworkType() == PeerNetwork::CONSENSUS ? "Consensus" : "Transaction", peerp.ip().c_str(), peerp.port());
			peer->GetPeerNetwork()->AddReceivedPeers(values);
		}

		return true;
	}

	bool PeerManager::OnGetPeers(const PeerMessagePointer &message, Peer *peer){
		return peer->SendPeers(peer->GetPeerNetwork()->GetPeersCache());
	}

	bool PeerManager::OnHello(const PeerMessagePointer &message, Peer *peer){
		do {
			PeerNetwork *network = peer->GetPeerNetwork();
			const  protocol::Hello *hello = (const protocol::Hello *)message->data_;

			peer->SetPeerInfo(*hello);

			if ((network->GetNetworkType() == PeerNetwork::CONSENSUS && hello->network_type() != bubi::General::CONSENSUS_NET_MAGICWORD)
				|| (network->GetNetworkType() == PeerNetwork::TRANSACTION && hello->network_type() != bubi::General::TRANSACTION_NET_MAGICWORD))
			{
				LOG_ERROR("Wrong network connection %s from %s(%s)", hello->network_type().c_str(), hello->nodeid().c_str(), peer->GetPeerAddress().ToIpPort().c_str());
				break;
			}

            if (network->NodeExist(hello->nodeid(), peer->peer_id()))
            {
                LOG_ERROR("disconnect duplicated connection with %s", peer->GetPeerAddress().ToIp().c_str());
                break;
            }

			if (peer_node_address_ == hello->nodeid()){
				LOG_ERROR("Peer connect self break");
				break;
			}

			if (hello->overlayversion() < bubi::General::OVERLAY_MIN_VERSION){
				LOG_ERROR("Peer's overlay version(%d) is too old,", hello->overlayversion());
				break;
			}
			if (hello->ledger_version() < bubi::General::LEDGER_MIN_VERSION){
				LOG_ERROR("Peer's leger version(%d) is too old,", hello->ledger_version());
				break;
			}
			if (hello->listeningport() <= 0 ||
				hello->listeningport() > utils::MAX_UINT16){
				LOG_ERROR("Peer's listen port(%d) is not valid", hello->listeningport());
				break;
			}

			LOG_INFO("Recv hello, peer(%s) is active", peer->GetRemoteAddress().ToIpPort().c_str());
			peer->SetActiveTime(utils::Timestamp::HighResolution());
			peer->SetStateChanged(true);

			if (peer->in_bound()){
				//发送 hello 消息
				const P2pNetwork &p2p_configure =
					network->GetNetworkType() == PeerNetwork::CONSENSUS
					? bubi::Configure::Instance().p2p_configure_.consensus_network_configure_
					: bubi::Configure::Instance().p2p_configure_.transaction_network_configure_;

				peer->SendHello(p2p_configure.listen_port_, peer_node_address_,
					network->GetNetworkType() == PeerNetwork::CONSENSUS ?
					bubi::General::CONSENSUS_NET_MAGICWORD : bubi::General::TRANSACTION_NET_MAGICWORD);
				//发送 Peers 
			}
			else{
			}

			return true;
		} while (false);

		peer->OnError();
		return false;
	}

	void PeerManager::OnPeerReceive(Peer *peer) {
		PeerNetwork *network = peer->GetPeerNetwork();
		if (network) {
			network->OnStartReceive();
		}
	}

	void PeerManager::OnPeerConnect(Peer *peer){
		PeerNetwork *network = peer->GetPeerNetwork();
		const P2pNetwork &p2p_configure =
			network->GetNetworkType() == PeerNetwork::CONSENSUS
			? bubi::Configure::Instance().p2p_configure_.consensus_network_configure_
			: bubi::Configure::Instance().p2p_configure_.transaction_network_configure_;

		peer->SendHello(p2p_configure.listen_port_, peer_node_address_,
			network->GetNetworkType() == PeerNetwork::CONSENSUS ?
			bubi::General::CONSENSUS_NET_MAGICWORD : bubi::General::TRANSACTION_NET_MAGICWORD);
	}

	bool PeerManager::OnDontHave(const PeerMessagePointer &message, Peer *peer){
		const protocol::DontHave *env = (const protocol::DontHave *)message->data_;
//		GlueManager::Instance().peerDoesntHave(env->type(), env->hash(), peer->peer_id());
		LOG_TRACE("On donthave");
		return true;
	}

	bool PeerManager::OnPing(const PeerMessagePointer &message, Peer *peer){
		const protocol::Ping *ping = (const protocol::Ping *)message->data_;
		return peer->SendPong(ping->nonce());
	}

	bool PeerManager::OnPong(const PeerMessagePointer &message, Peer *peer){
		int64_t now = utils::Timestamp::HighResolution();
		peer->UpdateDelay(now);
		return true;
	}

	bool PeerManager::OnTransactionLite(const PeerMessagePointer &message, Peer *peer){
	
		if (!consensus_network_.ReceiveBroadcastMsg(message, peer->peer_id()))
		{
			return false;
		}

		const protocol::TransactionLite *env = (const protocol::TransactionLite *)message->data_;
		ConsenterManager::Instance().OnTransaction(*env);
		return true;
	}

	void PeerManager::GetModuleStatus(Json::Value &data){
		data["name"] = "peer_manager";
		data["peer_node_address"] = peer_node_address_;
		consensus_network_.GetModuleStatus(data["consensus_network"]);
	}

	void PeerManager::OnSlowTimer(int64_t current_time) {
		if (!cert_enabled_) {
			return;
		}
		// check certificate status
		uint64_t now_time = utils::Timestamp::HighResolution();
		if (now_time - ca_last_time_ > 5 * 60 * utils::MICRO_UNITS_PER_SEC) {
			do {
				if (serial_num_.empty()) break;
				bubi::CAServerConfigure& ca_server_configure = bubi::Configure::Instance().p2p_configure_.ca_server_configure_;
				bubi::CAManager ca;
				utils::CAStatusMap ca_list;
				char out_msg[256] = { 0 };
				if (!ca.GetCertificatList(ca_server_configure, serial_num_, &ca_list, out_msg)) {
					break;
				}
				utils::MutexGuard guard(ca_list_mutex_);
				ca_list_ = ca_list;
			} while (false);
			ca_last_time_ = now_time;
		}
	}

}
