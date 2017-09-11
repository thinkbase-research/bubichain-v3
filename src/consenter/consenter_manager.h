#ifndef CONSENTER_MANAGER_H_
#define CONSENTER_MANAGER_H_

#include <common/general.h>
#include <common/storage.h>
#include <consensus/consensus_manager.h>
#include "consenter.pb.h"

namespace bubi {
	extern const char *TXLITE_TABLE_NAME;
	//transaction lite frame
	class TransactionLiteFrm {
		protocol::TransactionLite raw_tx_;
	public:
		TransactionLiteFrm();
		TransactionLiteFrm(const protocol::TransactionLite &tx);
		~TransactionLiteFrm();

		std::string GetTopic() const;
		int64_t GetSeq() const;
		std::string GetHash();
		void ToJson(Json::Value &json) const;
		const protocol::TransactionLite &GetRaw() const;
		static bool Load(RationalDb *db, const std::string &hash, Json::Value &record);
	};
	typedef std::shared_ptr<TransactionLiteFrm> TransactionLiteFrmPtr;

	//transaction lite set frame
	class TransactionLiteSetFrm{
		protocol::TransactionLiteSet raw_txs_;
		std::map<std::string, int64_t> topic_seqs_;
	public:
		TransactionLiteSetFrm(const std::string &preledger_hash);
		TransactionLiteSetFrm(const protocol::TransactionLiteSet &env);
		~TransactionLiteSetFrm();
		bool Add(const TransactionLiteFrmPtr &tx);
		std::string GetSerializeString() const;
		int32_t Size() const;
		const protocol::TransactionLiteSet &GetRaw() const;
	};
	typedef std::map<int64_t, TransactionLiteFrmPtr> TransactionLiteFrmMap;

	//ledger header lite frame
	class LedgerHeaderLiteFrm{
		protocol::LedgerHeaderLite header_;
	public:
		LedgerHeaderLiteFrm();
		LedgerHeaderLiteFrm(const protocol::LedgerHeaderLite &header);
		~LedgerHeaderLiteFrm();

		int64_t GetSeq() const;
		int64_t GetTxCount() const;
		std::string GetHash() const;
		int64_t GetTime() const;
		void From(const protocol::TransactionLiteSet &txset, int64_t time, int64_t sequence, int64_t last_tx_count);
		void FromJson(const Json::Value &value);
		void ToJson(Json::Value &value) const;
		void ToStringMap(utils::StringMap &value) const;
		bool Load(RationalDb *db, int64_t sequence);
	};
	typedef std::shared_ptr<LedgerHeaderLiteFrm> LedgerHeaderLiteFrmPtr;

	//topic key
	class TopicKey{
		std::string topic_;
		int64_t sequence_;
	public:
		TopicKey();
		TopicKey(const std::string &topic, int64_t sequence);
		~TopicKey();

		const std::string &GetTopic() const;
		const int64_t GetSeq() const;

		bool operator<(const TopicKey &key) const ;
	};

	typedef std::map<TopicKey, TransactionLiteFrmPtr> TransactionLiteMap;

	class ConsenterManager : public utils::Singleton < bubi::ConsenterManager>,
		public bubi::TimerNotify,
		public bubi::StatusModule,
		public IConsensusNotify{

		friend class TransactionLiteSetFrm;

		std::map<std::string, int64_t> last_topic_seqs_;
		TransactionLiteMap topic_caches_;
		LedgerHeaderLiteFrmPtr last_ledger_;

		int64_t time_start_consenus_;
		std::shared_ptr<Consensus> consensus_;

		int64_t ledgerclose_check_timer_;

		bool LoadLastLedger();
		bool CreateGenesisLedger();
		void StartLedgerCloseTimer();
	public:
		ConsenterManager();
		~ConsenterManager();

		bool Initialize();
		bool Exit();

		bool StartConsensus(); //start to trigger consensus
		bool CreateTableIfNotExist(); //create the db
		std::string CalculateTxTreeHash(const std::vector<TransactionLiteFrmPtr> &tx_array);
		size_t RemoveTxset(const TransactionLiteSetFrm &set);
		const LedgerHeaderLiteFrmPtr GetLastLedger() const{ return last_ledger_; };

		void OnTransaction(const protocol::TransactionLite &env);
		void OnConsensus(const ConsensusMsg &msg);

		virtual void OnTimer(int64_t current_time) override;
		virtual void OnSlowTimer(int64_t current_time) override{};
		virtual void GetModuleStatus(Json::Value &data);

		// IConsensusNotify
		virtual std::string OnValueCommited(int64_t block_seq, int64_t request_seq, const protocol::Value &value, bool calculate_total);
		virtual void OnViewChanged();
		virtual int32_t CheckValue(int64_t block_seq, const protocol::Value &value);
		virtual void SendConsensusMessage(const PeerMessagePointer &message);
		virtual std::string FetchNullMsg();
	};
}

#endif