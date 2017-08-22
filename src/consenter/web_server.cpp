#include <utils/headers.h>
#include <common/general.h>
#include <common/configure.h>
#include <common/private_key.h>
#include <consensus/consensus_manager.h>
#include "consenter_manager.h"
#include "peer_manager.h"
#include "web_server.h"

namespace bubi {

	WebServer::WebServer() :
		async_io_ptr_(NULL),
		server_ptr_(NULL),
		context_(NULL),
		rational_db_(NULL),
		running(NULL)
	{
	}

	WebServer::~WebServer() {
	}

	bool WebServer::Initialize(WebServerConfigure &webserver_config) {
		if (webserver_config.listen_addresses_.size() == 0) {
			LOG_INFO("Listen address not set, ignore");
			return true;
		}

		rational_db_ = Storage::Instance().OpenRationalDb();
		if (!rational_db_) {
			return false;
		}

		if (webserver_config.ssl_enable_) {
			std::string strHome = utils::File::GetBinHome();
			context_ = new asio::ssl::context(asio::ssl::context::tlsv12);
			context_->set_options(
				asio::ssl::context::default_workarounds
				| asio::ssl::context::no_sslv2
				| asio::ssl::context::single_dh_use);
			context_->set_password_callback(std::bind(&WebServer::GetCertPassword, this, std::placeholders::_1, std::placeholders::_2));
			context_->use_certificate_chain_file(utils::String::Format("%s/%s", strHome.c_str(), webserver_config.ssl_configure_.chain_file_.c_str()));
			asio::error_code ignore_code;
			context_->use_private_key_file(utils::String::Format("%s/%s", strHome.c_str(), webserver_config.ssl_configure_.private_key_file_.c_str()),
				asio::ssl::context::pem,
				ignore_code);
			context_->use_tmp_dh_file(utils::String::Format("%s/%s", strHome.c_str(), webserver_config.ssl_configure_.dhparam_file_.c_str()));
		}

		utils::InetAddress address = webserver_config.listen_addresses_.front();
		server_ptr_ = new http::server::server(address.ToIp(), address.GetPort(), context_, 8);

		server_ptr_->add404(std::bind(&WebServer::FileNotFound, this, std::placeholders::_1, std::placeholders::_2));
		server_ptr_->addRoute("hello", std::bind(&WebServer::Hello, this, std::placeholders::_1, std::placeholders::_2));
		server_ptr_->addRoute("createAccount", std::bind(&WebServer::CreateAccount, this, std::placeholders::_1, std::placeholders::_2));
		server_ptr_->addRoute("getAccount", std::bind(&WebServer::GetAccount, this, std::placeholders::_1, std::placeholders::_2));
		server_ptr_->addRoute("getLedger", std::bind(&WebServer::GetLedger, this, std::placeholders::_1, std::placeholders::_2));
		server_ptr_->addRoute("getConsensusInfo", std::bind(&WebServer::GetConsensusInfo, this, std::placeholders::_1, std::placeholders::_2));
		server_ptr_->addRoute("getModulesStatus", std::bind(&WebServer::GetModulesStatus, this, std::placeholders::_1, std::placeholders::_2));
		server_ptr_->addRoute("getTransactionHistory", std::bind(&WebServer::GetTransactionHistory, this, std::placeholders::_1, std::placeholders::_2));

		server_ptr_->addRoute("mutliQuery", std::bind(&WebServer::MultiQuery, this, std::placeholders::_1, std::placeholders::_2));
		server_ptr_->addRoute("submitTransaction", std::bind(&WebServer::SubmitTransaction, this, std::placeholders::_1, std::placeholders::_2));

		server_ptr_->Run();
		running = true;

		LOG_INFO("Webserver started, listen at %s", address.ToIpPort().c_str());

		return true;
	}

	bool WebServer::Exit() {
		LOG_INFO("WebServer stoping...");
		running = false;
		if (server_ptr_) {
			server_ptr_->Stop();
			delete server_ptr_;
			server_ptr_ = NULL;
		}

		if (context_) {
			delete context_;
			context_ = NULL;
		}
		LOG_INFO("WebServer stop [OK]");
		return true;
	}

	std::string WebServer::GetCertPassword(std::size_t, asio::ssl::context_base::password_purpose purpose) {
		return bubi::Configure::Instance().webserver_configure_.ssl_configure_.private_password_;
	}

	void WebServer::FileNotFound(const http::server::request &request, std::string &reply) {
		reply = "File not found";
	}

	void WebServer::Hello(const http::server::request &request, std::string &reply) {
		Json::Value reply_json = Json::Value(Json::objectValue);
		reply_json["bubi_version"] = General::BUBI_VERSION;
		reply_json["ledger_version"] = utils::String::ToString(General::LEDGER_VERSION);
		reply_json["overlay_version"] = utils::String::ToString(General::OVERLAY_VERSION);
		reply_json["current_time"] = utils::Timestamp::Now().ToFormatString(true);
		reply = reply_json.toFastString();
	}

	void WebServer::MultiQuery(const http::server::request &request, std::string &reply){
		WebServerConfigure &web_config = Configure::Instance().webserver_configure_;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value &results = reply_json["results"];

		do {
			Json::Value req;
			if (!req.fromString(request.body)) {
				LOG_ERROR("Parse request body json failed");
				reply_json["error_code"] = protocol::ERRCODE_INVALID_PARAMETER;
				break;
			}

			const Json::Value &items = req["items"];

			if (items.size() > web_config.multiquery_limit_){
				LOG_ERROR("MultiQuery size is too larger than %u", web_config.multiquery_limit_);
				reply_json["error_code"] = protocol::ERRCODE_INVALID_PARAMETER;
				break;
			}

			for (uint32_t i = 0; i < items.size(); i++){
				const Json::Value &item = items[i];
				Json::Value &result = results[i];
				std::string url = item["url"].asString();
				std::string method = item["method"].asString();

				http::server::request request_inner;
				if (item.isMember("jsonData"))
				{
					const Json::Value &nRequestJsonData = item["jsonData"];
					if (nRequestJsonData.isString())
					{
						request_inner.body = nRequestJsonData.asString();
					}
					else
					{
						request_inner.body = nRequestJsonData.toFastString();
					}
				}

				std::string reply_inner;
				request_inner.uri = url;
				request_inner.method = method;
				request_inner.Update();

				http::server::server::routeHandler *handle = server_ptr_->getRoute(request_inner.command);
				if (handle){
					(*handle)(request_inner, reply_inner);
				}

				result.fromString(reply_inner);
			}

			reply_json["error_code"] = 0;
		} while (false);

		reply = reply_json.toStyledString();
	}

	void WebServer::GetModuleStatus(Json::Value &data) {
		data["name"] = "web server";
		data["context"] = (context_ != NULL);
	}

	void WebServer::GetModulesStatus(const http::server::request &request, std::string &reply){
		utils::ReadLockGuard guard(bubi::StatusModule::status_lock_);
		Json::Value reply_json = *bubi::StatusModule::modules_status_;

		reply_json["keyvalue_db"] = Json::Value(Json::objectValue);
		bubi::Storage::Instance().keyvalue_db()->GetOptions(reply_json["keyvalue_db"]);

		reply = reply_json.toStyledString();
	}

	void WebServer::SubmitTransaction(const http::server::request &request, std::string &reply){
		Json::Value body;
		if (!body.fromString(request.body)) {
			LOG_ERROR("Parse request body json failed");
			Json::Value reply_json;
			reply_json["results"][Json::UInt(0)]["error_code"] = protocol::ERRCODE_INVALID_PARAMETER;
			reply_json["results"][Json::UInt(0)]["error_desc"] = "request must being json format";
			reply_json["success_count"] = Json::UInt(0);
			reply = reply_json.toStyledString();
			return;
		}

		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value &results = reply_json["results"];
		results = Json::Value(Json::arrayValue);
		uint32_t success_count = 0;

		int64_t begin_time = utils::Timestamp::HighResolution();
		const Json::Value &json_items = body["items"];
		for (size_t j = 0; j < json_items.size() && running; j++) {
			const Json::Value &json_item = json_items[j];
			Json::Value &result_item = results[results.size()];

			protocol::TransactionLite txlite;
			std::string topic = json_item["topic"].asString();
			if (topic.empty()) topic = utils::String::Format("topic" FMT_I64, utils::Timestamp::HighResolution());
			txlite.set_topic(topic);
			txlite.set_sequence(1);
			txlite.set_operation(json_item["operation"].asString());
			Global::Instance().GetIoService().post([this, txlite]{

				ConsenterManager::Instance().OnTransaction(txlite);

				//broadcast
				PeerMessagePointer message = PeerMessageWithLite::NewTransactionLite();
				*(protocol::TransactionLite *)message->data_ = txlite;
				PeerManager::Instance().Broadcast(message);
			});

			result_item["hash"] = utils::String::BinToHexString(utils::Sha256::Crypto(txlite.SerializeAsString()));
			result_item["topic"] = topic;
			result_item["sequence"] = 1;
		}

		reply = reply_json.toStyledString();
	}

	void WebServer::GetConsensusInfo(const http::server::request &request, std::string &reply) {

		Json::Value root;
		ConsensusManager::Instance().GetConsensus()->GetModuleStatus(root);
		reply = root.toStyledString();
	}

	void WebServer::GetLedger(const http::server::request &request, std::string &reply){
		std::string ledger_seq = request.GetParamValue("seq");

		/// default last closed ledger
		if (ledger_seq.empty())
			ledger_seq = utils::String::ToString(ConsenterManager::Instance().GetLastLedger()->GetSeq());


		int32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);
		Json::Value record = Json::Value(Json::arrayValue);
		Json::Value &result = reply_json["result"];

		ledger_seq = rational_db_->Format(ledger_seq);
		LedgerHeaderLiteFrm frm;
		do
		{
			if (!frm.Load(rational_db_, utils::String::Stoi64(ledger_seq))) {
				error_code = protocol::ERRCODE_NOT_EXIST;
				break;
			}
			frm.ToJson(result);
		} while (false);

		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}

	void WebServer::CreateAccount(const http::server::request &request, std::string &reply){}

	void WebServer::GetAccount(const http::server::request &request, std::string &reply){}

	void WebServer::GetTransactionHistory(const http::server::request &request, std::string &reply) {
		WebServerConfigure &web_config = Configure::Instance().webserver_configure_;

		std::string topic = request.GetParamValue("topic");
		std::string seq = request.GetParamValue("ledger_seq");
		std::string hash = request.GetParamValue("hash");
		std::string str_order = request.GetParamValue("order");
		std::string start_str = request.GetParamValue("start");
		std::string limit_str = request.GetParamValue("limit");

		if (str_order == "DESC" ||
			str_order == "desc" ||
			str_order == "asc" ||
			str_order == "ASC") {
		}
		else {
			str_order = "DESC";
		}

		int32_t error_code = protocol::ERRCODE_SUCCESS;
		Json::Value reply_json = Json::Value(Json::objectValue);

		Json::Value &result = reply_json["result"];
		Json::Value &txs = result["transactions"];
		txs = Json::Value(Json::arrayValue);
		do{
			if (start_str.empty()) start_str = "0";
			if (!utils::String::is_number(start_str) == 1){
				error_code = protocol::ERRCODE_INVALID_PARAMETER;
				break;
			}
			uint32_t start = utils::String::Stoui(start_str);


			if (limit_str.empty()) limit_str = "20";
			if (!utils::String::is_number(limit_str) == 1){
				error_code = protocol::ERRCODE_INVALID_PARAMETER;
				break;
			}
			uint32_t limit = utils::String::Stoui(limit_str);
			limit = MIN(limit, web_config.query_limit_);

			std::string table_name = TXLITE_TABLE_NAME;
			std::string condition = "WHERE 1=1 ";
			size_t condition_size = condition.size();
			if (!hash.empty()) {
				condition += utils::String::Format("AND hash='%s'", hash.c_str());
			}
			else if (!seq.empty()) {
				condition += utils::String::Format("AND ledger_seq=%s", seq.c_str());
			}

			if (!topic.empty()) {
				condition += utils::String::Format(" AND topic='%s' ", rational_db_->Format(topic).c_str());
			}

			std::string sql = utils::String::Format("SELECT * FROM %s %s ORDER BY seq_in_global %s OFFSET %u LIMIT %u",
				table_name.c_str(),
				condition.c_str(),
				str_order.c_str(),
				start, limit);

			//avoid scan the whole table
			if (condition.size() == condition_size){
				const LedgerHeaderLiteFrmPtr  &header = ConsenterManager::Instance().GetLastLedger();
				result["total_count"] = header->GetTxCount();
			}
			else{
				Json::Value ret;
				int32_t nret = rational_db_->QueryRecord(utils::String::Format("SELECT COUNT(hash) AS count FROM %s %s", table_name.c_str(), condition.c_str()), ret);
				if (nret < 0) {
					LOG_ERROR_ERRNO("excute query failed",
						rational_db_->error_code(), rational_db_->error_desc());
					error_code = protocol::ERRCODE_INTERNAL_ERROR;
					break;
				}
				result["total_count"] = ret["count"].asInt64();
			}

			Json::Value record;
			if (rational_db_->Query(sql, txs) < 0) {
				LOG_ERROR_ERRNO("query sql(%s) failed", sql.c_str(), rational_db_->error_code(), rational_db_->error_desc());
				error_code = protocol::ERRCODE_INTERNAL_ERROR;
				break;
			}

			if (record.size() == 0) {
				error_code = protocol::ERRCODE_NOT_EXIST;
				break;
			}
		} while (false);

		reply_json["error_code"] = error_code;
		reply = reply_json.toStyledString();
	}
}