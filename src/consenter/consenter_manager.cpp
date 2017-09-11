#include <common/storage.h>
#include "consenter.pb.h"
#include "peer_manager.h"
#include "consenter_manager.h"

namespace bubi {
	const char *LEDGERLITE_TABLE_NAME = "ledger_lite";
	const char *LEDGERLITE_CREATE_SQL =
		"CREATE TABLE ledger_lite("
		"sequence	      INT  NOT NULL,"
		"hash			  VARCHAR(70)   NOT NULL DEFAULT '', "
		"phash			  VARCHAR(70)   NOT NULL DEFAULT '',"
		"txs_hash			  VARCHAR(70)   NOT NULL DEFAULT '',"
		"consensus_value  VARCHAR(1024) NOT NULL DEFAULT '',"
		"tx_count         BIGINT        NOT NULL DEFAULT 1,"
		"apply_time      BIGINT       NOT NULL DEFAULT 0,   "
		"PRIMARY KEY   (sequence)                        "
		");"
		;

	const char *TXLITE_TABLE_NAME = "transaction_lite_history";
	const char *TXLITE_CREATE_SQL =
		"CREATE TABLE transaction_lite_history("
		"hash			 VARCHAR(64)  NOT NULL DEFAULT '', "
		"topic			VARCHAR(64)  NOT NULL DEFAULT '', "
		"ledger_seq		 BIGINT       NOT NULL DEFAULT 0,  "
		"sequence		 BIGINT       NOT NULL DEFAULT 0,  "
		"body			 TEXT         NOT NULL , "
		"result			 TEXT		  NOT NULL , "
		"error_code		 INT          NOT NULL DEFAULT 0,  "
		"seq_in_global   BIGINT       NOT NULL DEFAULT 0,  "
		"apply_time      BIGINT       NOT NULL DEFAULT 0,   "
		"PRIMARY KEY   (hash)"
		");"
		"CREATE INDEX  index_ledger_seq ON transaction_lite_history(ledger_seq);"
		"CREATE INDEX  index_seq_in_global ON transaction_lite_history(seq_in_global);"
		;


	const char *TOPIC_TABLE_NAME = "topic";
	const char *TOPIC_CREATE_SQL =
		"CREATE TABLE topic("
		"name	      VARCHAR(70)  NOT NULL,"
		"sequence     BIGINT        NOT NULL DEFAULT 1,"
		"PRIMARY KEY   (name)                        "
		");";


	TransactionLiteFrm::TransactionLiteFrm(){}
	TransactionLiteFrm::TransactionLiteFrm(const protocol::TransactionLite &tx) : raw_tx_(tx){
	}
	TransactionLiteFrm::~TransactionLiteFrm(){};
	std::string TransactionLiteFrm::GetHash(){
		return utils::Sha256::Crypto(raw_tx_.SerializeAsString());
	}

	std::string TransactionLiteFrm::GetTopic() const{
		return raw_tx_.topic();
	}

	int64_t TransactionLiteFrm::GetSeq() const{
		return raw_tx_.sequence();
	}

	void TransactionLiteFrm::ToJson(Json::Value &json) const{
		json["topic"] = raw_tx_.topic();
		json["sequence"] = raw_tx_.sequence();
	}

	bool TransactionLiteFrm::Load(RationalDb *db, const std::string &hash, Json::Value &record){
		std::string tx_sql_where = utils::String::Format("WHERE hash='" FMT_I64 "'", hash.c_str());
		int32_t nret = db->QueryRecord(TXLITE_TABLE_NAME, tx_sql_where, record);
		if (nret < 0) {
			LOG_ERROR_ERRNO("query sql(%s) fail", tx_sql_where.c_str(), db->error_code(), db->error_desc());
			return false;
		}
		else if (nret == 0){
			return false;
		}

		return true;
	}

	const protocol::TransactionLite &TransactionLiteFrm::GetRaw() const{
		return raw_tx_;
	}

	TransactionLiteSetFrm::TransactionLiteSetFrm(const std::string &preledger_hash){
		raw_txs_.set_preledger_hash(preledger_hash);
	}

	TransactionLiteSetFrm::TransactionLiteSetFrm(const protocol::TransactionLiteSet &env){
		raw_txs_ = env;
	}

	TransactionLiteSetFrm::~TransactionLiteSetFrm(){}
	bool TransactionLiteSetFrm::Add(const TransactionLiteFrmPtr &tx){

		int64_t last_seq = 0;
		do {
			//find this cache
			std::map<std::string, int64_t>::iterator this_iter = topic_seqs_.find(tx->GetTopic());
			if (this_iter != topic_seqs_.end()){
				last_seq = this_iter->second;
				break;
			}

			//find global cache
			std::map<std::string, int64_t> &last_topic = ConsenterManager::Instance().last_topic_seqs_;
			std::map<std::string, int64_t>::iterator iter = last_topic.find(tx->GetTopic());
			if (iter != last_topic.end()){
				last_seq = iter->second;
			}
		} while (false);

		if (tx->GetSeq() != last_seq + 1){
			LOG_ERROR("The tx seq(" FMT_I64 ") is not equal of last seq(" FMT_I64 ") + 1", tx->GetSeq(), last_seq);
			return false;
		}

		topic_seqs_.insert(std::make_pair(tx->GetTopic(), tx->GetSeq()));
		*raw_txs_.add_txs() = tx->GetRaw();
		return true;
	}

	std::string TransactionLiteSetFrm::GetSerializeString() const{
		return raw_txs_.SerializeAsString();
	}

	int32_t TransactionLiteSetFrm::Size() const{
		return raw_txs_.txs_size();
	}

	const protocol::TransactionLiteSet &TransactionLiteSetFrm::GetRaw() const{
		return raw_txs_;
	}

	TopicKey::TopicKey() : sequence_(0){}
	TopicKey::TopicKey(const std::string &topic, int64_t sequence) :topic_(topic), sequence_(sequence)
	{}
	TopicKey::~TopicKey(){}

	bool TopicKey::operator<(const TopicKey &key) const{
		if (topic_ < key.topic_){
			return true;
		} else if( topic_ == key.topic_ && sequence_ < key.sequence_){
			return true;
		}

		return false;
	}

	const std::string &TopicKey::GetTopic() const{
		return topic_;
	}

	const int64_t TopicKey::GetSeq() const{
		return sequence_;
	}

	LedgerHeaderLiteFrm::LedgerHeaderLiteFrm(){}
	LedgerHeaderLiteFrm::~LedgerHeaderLiteFrm(){}

	LedgerHeaderLiteFrm::LedgerHeaderLiteFrm(const protocol::LedgerHeaderLite &header):header_(header){}

	void LedgerHeaderLiteFrm::FromJson(const Json::Value &value){
		header_.set_sequence(value["sequence"].asInt64());
		header_.set_hash(utils::String::HexStringToBin(value["hash"].asString()));
		header_.set_phash(utils::String::HexStringToBin(value["phash"].asString()));
		header_.set_txs_hash(utils::String::HexStringToBin(value["txs_hash"].asString()));
		header_.set_apply_time(value["apply_time"].asInt64());
		header_.set_tx_count(value["tx_count"].asInt64());
	}

	void LedgerHeaderLiteFrm::ToJson(Json::Value &value) const {
		value["ledger_sequence"] = header_.sequence();
		value["hash"] = utils::String::BinToHexString(header_.hash());
		value["phash"] = utils::String::BinToHexString(header_.phash());
		value["txs_hash"] = utils::String::BinToHexString(header_.txs_hash());
		value["apply_time"] = header_.apply_time();
		value["tx_count"] = header_.tx_count();
	}

	void LedgerHeaderLiteFrm::ToStringMap(utils::StringMap &value) const{
		value["sequence"] = utils::String::ToString(header_.sequence());
		value["hash"] = utils::String::BinToHexString(header_.hash());
		value["phash"] = utils::String::BinToHexString(header_.phash());
		value["txs_hash"] = utils::String::BinToHexString(header_.txs_hash());
		value["apply_time"] = utils::String::ToString(header_.apply_time());
		value["tx_count"] = utils::String::ToString(header_.tx_count());
	}

	bool LedgerHeaderLiteFrm::Load(RationalDb *db, int64_t sequence){
		std::string ledger_sql_where = utils::String::Format("WHERE sequence=" FMT_I64, sequence);
		Json::Value record1;
		int32_t nret = db->QueryRecord(LEDGERLITE_TABLE_NAME, ledger_sql_where, record1);
		if (nret < 0) {
			LOG_ERROR_ERRNO("query sql(%s) fail", ledger_sql_where.c_str(), db->error_code(), db->error_desc());
			return false;
		}

		FromJson(record1);
		return true;
	}

	int64_t LedgerHeaderLiteFrm::GetSeq() const {
		return header_.sequence();
	}

	int64_t LedgerHeaderLiteFrm::GetTxCount() const{
		return header_.tx_count();
	}

	std::string LedgerHeaderLiteFrm::GetHash() const{
		return header_.hash();
	}

	int64_t LedgerHeaderLiteFrm::GetTime() const{
		return header_.apply_time();
	}

	void LedgerHeaderLiteFrm::From(const protocol::TransactionLiteSet &txset, int64_t time, int64_t sequence, int64_t last_tx_count){
		header_.set_hash("");
		header_.set_sequence(sequence);
		header_.set_phash(txset.preledger_hash());
		header_.set_txs_hash(utils::Sha256::Crypto(txset.SerializeAsString()));
		header_.set_apply_time(time);
		header_.set_tx_count(txset.txs_size() + last_tx_count);
		header_.set_hash(utils::Sha256::Crypto(header_.SerializeAsString()));
	}

	ConsenterManager::ConsenterManager(){
		time_start_consenus_ = 0;
		ledgerclose_check_timer_ = 0;
		last_ledger_ = std::make_shared<LedgerHeaderLiteFrm>();
	}
	ConsenterManager::~ConsenterManager(){}

	bool ConsenterManager::Initialize(){
		CreateTableIfNotExist();

		//get last topic
		RationalDb *db = Storage::Instance().rational_db();
		Json::Value result;
		std::string sql = utils::String::Format("select * from %s", TOPIC_TABLE_NAME);
		if (db->Query(sql, result) < 0){
			LOG_ERROR_ERRNO("Query table(%s) failed", sql.c_str(), db->error_code(), db->error_desc());
			return false;
		}

		for (size_t i = 0; i < result.size(); i++){
			const Json::Value &item = result[i];
			last_topic_seqs_[item["name"].asString()] = item["seq"].asInt64();
		}

		if (!LoadLastLedger()){
			return false;
		}

		consensus_ = ConsensusManager::Instance().GetConsensus();
		consensus_->SetNotify(this);
		StatusModule::RegisterModule(this);

		if (consensus_->RepairStatus()){
			//start consensus
			utils::Timer::Instance().AddTimer(3 * utils::MICRO_UNITS_PER_SEC, 0, [this](int64_t data){
				StartConsensus();
			});
		} 

		StartLedgerCloseTimer();

		LOG_INFO("Load " FMT_SIZE " topic(s), last ledger(seq:" FMT_I64 ") from db", last_topic_seqs_.size(), last_ledger_->GetSeq());
		return true;
	}

	bool ConsenterManager::LoadLastLedger(){
		//load last ledger
		RationalDb *db = Storage::Instance().rational_db();
		std::string max_ledger_sql = utils::String::Format("SELECT MAX(sequence) AS sequence FROM %s", LEDGERLITE_TABLE_NAME);
		Json::Value record;
		int32_t nret = db->QueryRecord(max_ledger_sql, record);
		if (nret <= 0) {
			LOG_ERROR_ERRNO("query sql(%s) fail", max_ledger_sql.c_str(), db->error_code(), db->error_desc());
			return false;
		}

		int64_t max_id = record["sequence"].asInt64();
		if (max_id == 0){
			return CreateGenesisLedger();
		}

		last_ledger_->Load(db, max_id);
		return true;
	}

	bool ConsenterManager::CreateGenesisLedger(){
		Json::Value value;

		std::vector<TransactionLiteFrmPtr> tx_array;
		protocol::LedgerHeaderLite gen_ledger;
		gen_ledger.set_hash("");
		gen_ledger.set_sequence(1);
		gen_ledger.set_phash("");
		gen_ledger.set_txs_hash(CalculateTxTreeHash(tx_array));
		gen_ledger.set_apply_time(0);
		gen_ledger.set_tx_count(0);
		gen_ledger.set_hash(utils::Sha256::Crypto(gen_ledger.SerializeAsString()));
		last_ledger_ = std::make_shared<LedgerHeaderLiteFrm>(gen_ledger);
		
		utils::StringMap values;
		last_ledger_->ToStringMap(values);
		RationalDb *db = Storage::Instance().rational_db();
		if (!db->Insert(LEDGERLITE_TABLE_NAME, values)){
			LOG_ERROR_ERRNO("Insert genesis ledger to db(table:%s) failed", LEDGERLITE_TABLE_NAME, db->error_code(), db->error_desc());
			return false;
		} 

		return true;
	}

	void ConsenterManager::StartLedgerCloseTimer(){
		//kill the ledger check timer
		utils::Timer::Instance().DelTimer(ledgerclose_check_timer_);
		ledgerclose_check_timer_ = utils::Timer::Instance().AddTimer(30 * utils::MICRO_UNITS_PER_SEC, 0,
			[this](int64_t data)
		{
			LOG_INFO("Ledger close timeout, call consensus view change");
			consensus_->OnTxTimeout();
		});
	}

	std::string ConsenterManager::CalculateTxTreeHash(const std::vector<TransactionLiteFrmPtr> &tx_array) {
		HashWrapper sha256;
		for (std::size_t i = 0; i < tx_array.size(); i++) {
			TransactionLiteFrmPtr env = tx_array[i];
			sha256.Update(env->GetHash());
		}
		return sha256.Final();
	}

	bool ConsenterManager::Exit(){
		return true; 
	}

	bool ConsenterManager::CreateTableIfNotExist(){
		RationalDb *db = Storage::Instance().rational_db();
		do {
			Json::Value columns;
			if (!db->DescribeTable(std::string(LEDGERLITE_TABLE_NAME), columns) &&
				!db->Execute(LEDGERLITE_CREATE_SQL)) {
				LOG_ERROR_ERRNO("Create table(%s) failed", LEDGERLITE_TABLE_NAME, db->error_code(), db->error_desc());
			}
			if (!db->DescribeTable(std::string(TXLITE_TABLE_NAME), columns) &&
				!db->Execute(TXLITE_CREATE_SQL)) {
				LOG_ERROR_ERRNO("Create table(%s) failed", TXLITE_TABLE_NAME, db->error_code(), db->error_desc());
			}
			if (!db->DescribeTable(std::string(TOPIC_TABLE_NAME), columns) &&
				!db->Execute(TOPIC_CREATE_SQL)) {
				LOG_ERROR_ERRNO("Create table(%s) failed", TOPIC_TABLE_NAME, db->error_code(), db->error_desc());
			}
		} while (false);
		return true;
	}

	bool ConsenterManager::StartConsensus(){
		//get cached tx, if error then delete it
		TransactionLiteSetFrm txset(last_ledger_->GetHash());
		size_t del_size = 0;
		for (TransactionLiteMap::iterator iter = topic_caches_.begin();
			iter != topic_caches_.end();){
			if (!txset.Add(iter->second)){
				iter = topic_caches_.erase(iter);
				del_size++;
			} else{
				iter++;
			}
		}

		int64_t next_close_time = utils::Timestamp::Now().timestamp();
		if (next_close_time <= last_ledger_->GetTime())
		{
			next_close_time = last_ledger_->GetTime() + utils::MICRO_UNITS_PER_SEC;
		}

		protocol::Value propose_value;
		propose_value.set_hash_set(txset.GetSerializeString());
		propose_value.set_close_time(next_close_time);

		time_start_consenus_ = utils::Timestamp::HighResolution();

		LOG_INFO("Proposed %d tx(s), removed " FMT_SIZE " tx(s)", txset.Size(), del_size);
		consensus_->Request(last_ledger_->GetSeq() + 1, propose_value);
		return true;
	}

	void ConsenterManager::OnTransaction(const protocol::TransactionLite &env){
		TransactionLiteFrmPtr tx = std::make_shared<TransactionLiteFrm>(env);
		TopicKey key(tx->GetTopic(), tx->GetSeq());
		TransactionLiteMap::iterator iter = topic_caches_.find(key);
		if (iter == topic_caches_.end()){
			LOG_INFO("Recv new tx(%s:" FMT_I64 ")", key.GetTopic().c_str(), key.GetSeq());
			topic_caches_.insert(std::make_pair(key, tx));
		}

		return;
	}

	void ConsenterManager::OnConsensus(const ConsensusMsg &msg){
		consensus_->OnRecv(msg);
	}

	void ConsenterManager::OnTimer(int64_t current_time){

	}

	size_t ConsenterManager::RemoveTxset(const TransactionLiteSetFrm &set) {
		size_t ret = 0;
		for (int32_t i = 0; i < set.GetRaw().txs_size(); i++){
			TransactionLiteFrm tx(set.GetRaw().txs(i));

			TransactionLiteMap::iterator iter = topic_caches_.find(TopicKey(tx.GetTopic(), tx.GetSeq()));
			if (iter != topic_caches_.end()){
				topic_caches_.erase(iter);
				ret++;
			} 
		}

		return ret;
	}

	std::string ConsenterManager::OnValueCommited(int64_t block_seq, int64_t request_seq, const protocol::Value &value, bool calculate_total){
		protocol::TransactionLiteSet txset;
		txset.ParseFromString(value.hash_set());
		TransactionLiteSetFrm txset_frm(txset);

		if (block_seq != last_ledger_->GetSeq() + 1){
			LOG_INFO("Block seq(" FMT_I64 ") is not equal than last seq(" FMT_I64 ") + 1",
				block_seq, last_ledger_->GetSeq());
			return "";
		} 

		//write to db
		RationalDb *db = Storage::Instance().rational_db();
		db->Begin();
		std::map<std::string, int64_t> tx_seqs;
		for (int32_t i = 0; i < txset.txs_size(); i++){
			const protocol::TransactionLite &tx = txset.txs(i);
			std::string sql = utils::String::Format(
				"INSERT INTO %s(hash,topic,ledger_seq,sequence,body,result,seq_in_global,apply_time) "
				"VALUES('%s','%s', " FMT_I64 ", " FMT_I64 ", '%s', '', " FMT_I64 ", " FMT_I64 ");",
				TXLITE_TABLE_NAME,
				utils::String::BinToHexString(utils::Sha256::Crypto(tx.SerializeAsString())).c_str(),
				tx.topic().c_str(), block_seq, tx.sequence(), utils::String::BinToHexString(tx.SerializeAsString()).c_str(),
				last_ledger_->GetTxCount() + i, value.close_time());

			std::map<std::string, int64_t>::iterator iter_find = tx_seqs.find(tx.topic());
			if (iter_find != tx_seqs.end()){
				if (iter_find->second < tx.sequence() ){
					tx_seqs[tx.topic()] = tx.sequence();
				}
			} else{
				tx_seqs[tx.topic()] = tx.sequence();
			}

			db->AppendSql(sql);
		}

		LedgerHeaderLiteFrmPtr header = std::make_shared<LedgerHeaderLiteFrm>();
		header->From(txset, value.close_time(), block_seq, last_ledger_->GetTxCount());
		Json::Value json_value;
		header->ToJson(json_value);

		//append ledger
		std::string sql = utils::String::Format(
			"INSERT INTO %s(sequence, hash, phash, txs_hash, consensus_value, tx_count,apply_time) "
			"VALUES(" FMT_I64 ",'%s', '%s', '%s', '%s', " FMT_I64 ", " FMT_I64 ");",
			LEDGERLITE_TABLE_NAME, 
			block_seq,
			json_value["hash"].asCString(), 
			json_value["phash"].asCString(),
			json_value["txs_hash"].asCString(),
			"",
			json_value["tx_count"].asInt64(),
			json_value["apply_time"].asInt64());
		db->AppendSql(sql);

		//append the topic
		for (std::map<std::string, int64_t>::iterator iter = tx_seqs.begin(); 
			iter != tx_seqs.end(); 
			iter++){
			int64_t seq = iter->second;
			std::string sql_topic;
			std::map<std::string, int64_t>::iterator iter_f = last_topic_seqs_.find(iter->first);
			if (iter_f != last_topic_seqs_.end()){
				sql_topic = utils::String::Format("UPDATE %s SET sequence=" FMT_I64 " WHERE name='%s';",
					TOPIC_TABLE_NAME, seq, iter->first.c_str());
			}
			else {
				sql_topic = utils::String::Format("INSERT INTO %s(name, sequence) VALUES('%s', " FMT_I64 ");",
					TOPIC_TABLE_NAME,iter->first.c_str(),seq);
			}
			last_topic_seqs_[iter->first] = iter->second;
			db->AppendSql(sql_topic);
		}

		int64_t time_start = utils::Timestamp::HighResolution();
		bool ret = db->Commit();
		if (!ret){
			LOG_ERROR_ERRNO("Commit new ledger(" FMT_I64 ") failed", block_seq, db->error_code(), db->error_desc());
			exit(0);
		} 
		int64_t time_use = utils::Timestamp::HighResolution() - time_start;

		//delete the cache
		size_t ret1 = RemoveTxset(txset_frm);

		//set header 
		last_ledger_ = header;

		//start time
		int64_t waiting_time = Configure::Instance().validation_configure_.close_interval_ - (utils::Timestamp::HighResolution() - time_start_consenus_);
		if (waiting_time <= 0)  waiting_time = 1;
		utils::Timer::Instance().AddTimer(waiting_time, 0, [this](int64_t data){
			StartConsensus();
		});

		StartLedgerCloseTimer();

		LOG_INFO("Close ledger(" FMT_I64 ") successful, use time(" FMT_I64 "ms)",
			block_seq, (int64_t)(time_use / utils::MILLI_UNITS_PER_SEC));
		
		return last_ledger_->GetHash();
	}

	void ConsenterManager::OnViewChanged(){
		LOG_INFO("Consenter on view changed");
		if (consensus_->RepairStatus()){
			StartConsensus();
			StartLedgerCloseTimer();
		}
	}

	int32_t ConsenterManager::CheckValue(int64_t block_seq, const protocol::Value &value){
		protocol::TransactionLiteSet txlite;
		txlite.ParseFromString(value.hash_set());
		TransactionLiteSetFrm txset(txlite);
		if (txset.GetRaw().preledger_hash() != last_ledger_->GetHash()){
			return Consensus::CHECK_VALUE_MAYVALID;
		} 
		return Consensus::CHECK_VALUE_VALID;
	}

	void ConsenterManager::SendConsensusMessage(const PeerMessagePointer &message){
		message->hash_ = utils::Sha256::Crypto(message->GetString());
		PeerManager::Instance().Broadcast(message);
		if (message->header_.type == PeerMessage::PEER_MESSAGE_PBFT){
			ConsensusMsg msg(*(protocol::PbftEnv *)message->data_);
			std::string block_seq_log = msg.GetBlockSeq() > 0 ? utils::String::Format(" block(" FMT_I64 ")", msg.GetBlockSeq()) : "";
			LOG_INFO("Receive consensus from self node address(%s) sequence(" FMT_I64 ")%s pbft type(%s)",
				msg.GetNodeAddress(), msg.GetSeq(), block_seq_log.c_str(), PbftDesc::GetMessageTypeDesc(msg.GetPbft().pbft().type()));
			consensus_->OnRecv(msg);
		}
	}

	std::string ConsenterManager::FetchNullMsg(){
		return "null";
	}

	void ConsenterManager::GetModuleStatus(Json::Value &data){
		data["name"] = "Consenter Manager";

		data["transaction_size"] = topic_caches_.size();
		last_ledger_->ToJson(data["last_ledger"]);
		data["cache_topic_size"] = last_topic_seqs_.size();
	}
}