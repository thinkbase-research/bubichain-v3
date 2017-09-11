#ifndef PEER_MANAGER_CON_H_
#define PEER_MANAGER_CON_H_

#include <utils/singleton.h>
#include <utils/net.h>
#include <common/general.h>
#include <common/private_key.h>
#include <overlay/broadcast.h>
#include <overlay/peer.h>

namespace bubi{

	class PeerMessageWithLite :public PeerMessage {

	public:
		typedef enum tagPEER_MESSAGE_TYPE
		{
			PEER_MESSAGE_TRANSACTIONLITE = 100,
		}PEER_MESSAGE_TYPE;

		PeerMessageWithLite();
		~PeerMessageWithLite();

		virtual bool FromStringOther(uint16_t type, const char* data, size_t len);

		static std::shared_ptr<PeerMessage> NewTransactionLite();
	};

	// 提供 P2P 网络的接口
	class IPeerManagerNotify{
	public:
		IPeerManagerNotify();
		~IPeerManagerNotify();

		virtual void OnNetworkPrepared() = 0;
		virtual void OnMessage() = 0;
	};

	typedef std::list<IPeerManagerNotify *> PeerManagerNotifier;

	class PeerNetwork :
		public utils::IAsyncSocketAcceptorNotify,
		public bubi::TimerNotify,
		public IBroadcastDriver
	{
	public:
		enum NetworkType{
			CONSENSUS = 0,
			TRANSACTION = 1
		};

		PeerNetwork(NetworkType type);
		~PeerNetwork();
	private:
		NetworkType type_;
		//异步IO对象，P2P网络所有操作共用这一个对象
		utils::AsyncIo *async_io_ptr_;
		asio::ssl::context context_;

		//指示启动后从DNS服务器读取IP状态
		bool dns_seed_inited_;

		//所有节点列表，包括活跃或者不活跃的
		PeerMap peer_list_;
		PeerMap peer_list_delete_;
		utils::Mutex peer_list_mutex_;
		int64_t last_heartbeart_time_;

		//Peer 数据列表
		Json::Value db_peer_cache_;

		//所有通知对象列表
		PeerManagerNotifier notifiers_;

		// Acceptor 监听器对象
		utils::AsyncSocketAcceptor *acceptor_ptr_;
		Peer *incoming_peer_;

		//存储接收到的对端的 Peers
		std::list<utils::StringMap> received_peer_list_;

		//广播类
		bubi::Broadcast broadcast_;

		//std::string peer_node_address_;
		//需要升级的验证节点列表
		utils::Mutex upgrad_request_envs_mutex_;
		std::map<std::string, std::shared_ptr<protocol::UpgradeRequestEnv>> upgrad_request_envs_;

		utils::Mutex validator_address_mutex_;
		std::string validator_address_;

		utils::Mutex ledger_version_mutex_;
		uint32_t ledger_version_;

		int64_t last_upgrad_request_time_;

		bool cert_enabled_;

		void Clean();

		std::string GetCertPassword(std::size_t, asio::ssl::context_base::password_purpose purpose);
		bool Listen();
		bool CheckStorage();

		bool ResolveSeeds(const utils::StringList &address_list, int32_t rank);
		bool ConnectToPeers(size_t max);
		bool LoadSeed();
		bool LoadHardcode();

		bool ResetPeerInActive();
		bool CreatePeerIfNotExist(const utils::InetAddress &address, int32_t rank);
		bool UpdatePeer(const utils::InetAddress &local_address, const utils::StringMap &values);
		bool GetActivePeers(int32_t max);

	public:
		bool Initialize(bool cert_enabled = false);
		bool Exit();

		bool RegisterNotify(IPeerManagerNotify *notify);
		Json::Value GetPeersCache();
		void AddReceivedPeers(const utils::StringMap &item);
		void Broadcast(const bubi::PeerMessagePointer &message);
		bool ReceiveBroadcastMsg(const bubi::PeerMessagePointer &message, int64_t peer_id);

		const PeerMap &GetPeers() const{ return peer_list_; };
		void GetPeers(Json::Value &peers);
		NetworkType GetNetworkType() const { return type_; };

		void OnStartReceive();
		virtual void OnAccept(utils::AsyncSocketAcceptor *acceptor_ptr);
		virtual void OnError(utils::AsyncSocketAcceptor *acceptor_ptr);
		virtual void OnTimer(int64_t current_time) override;
		virtual void OnSlowTimer(int64_t current_time) override{};
		void GetModuleStatus(Json::Value &data);

		virtual bool SendMessage(int64_t peer_id, PeerMessagePointer msg);
		virtual std::set<int64_t> GetActivePeerIds();

		bool NodeExist(std::string node_address, int64_t peer_id);

	};

	class PeerManager : public utils::Singleton<PeerManager>,
		public IPeerAppNotify,
		public StatusModule,
		public TimerNotify,
		public utils::Runnable
	{
		friend class utils::Singleton<PeerManager>;
	public:
		PeerManager();
		~PeerManager();

		bool Initialize(char *serial_num = NULL, bool cert_enabled = false);
		bool Exit();

		virtual void OnTimer(int64_t current_time) override {};
		virtual void OnSlowTimer(int64_t current_time);

		virtual void Run(utils::Thread *thread) override;

		void Broadcast(const bubi::PeerMessagePointer &message);
		bool SendMessage(int64_t peer_id, PeerMessagePointer &message);

		PeerNetwork& ConsensusNetwork(){ return consensus_network_; }
		asio::io_service& GetIOService(){ return asio_service_; }

		std::string GetPeerNodeAddress(){
			return priv_key_.GetBase16Address();
		}

		virtual bool OnAppMsgNotify(const PeerMessagePointer &message, Peer *peer_ptr);
		virtual int32_t OnTransactionNotify(const PeerMessagePointer &message, const std::string &buffer, Peer *peer_ptr);
		virtual void GetModuleStatus(Json::Value &data);
		virtual PeerMessagePointer GetMessageObject(){ return std::make_shared<PeerMessageWithLite>(); };

		bool BroadcastPayLoad(protocol::ChainPeerMessage &cpm);
	private:
		bool OnPbft(const PeerMessagePointer &message, Peer *peer);
		bool OnPeers(const PeerMessagePointer &message, Peer *peer);
		bool OnGetPeers(const PeerMessagePointer &message, Peer *peer);
		bool OnHello(const PeerMessagePointer &message, Peer *peer);
		bool OnDontHave(const PeerMessagePointer &message, Peer *peer);
		bool OnPing(const PeerMessagePointer &message, Peer *peer);
		bool OnPong(const PeerMessagePointer &message, Peer *peer);
		bool OnTransactionLite(const PeerMessagePointer &message, Peer *peer);
		void OnPeerConnect(Peer *peer);
		void OnPeerReceive(Peer *peer);
		bool OnPayLoad(const PeerMessagePointer &message, Peer *peer);

		//high way to deliver urgent message asap
		PeerNetwork consensus_network_;
		//one-way network, only for broadcasting transaction 
		//PeerNetwork transaction_network_;
		MessagePeerPocMap peer_methods_;

		asio::io_service asio_service_;
		utils::Thread *thread_ptr_;
		PrivateKey priv_key_;
		std::string peer_node_address_;

		bool cert_enabled_;
		uint64_t ca_last_time_;
		std::string serial_num_;
		utils::Mutex ca_list_mutex_;
		utils::CAStatusMap ca_list_;
	};
}

#endif

