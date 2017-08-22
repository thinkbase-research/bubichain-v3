#include <gtest/gtest.h>
#include "web_socket_server.h"
#include <utils/crypto.h>
#include <utils/logger.h>
#include <utils/thread.h>
#include <utils/timestamp.h>
#include <sys/types.h>  
#include <sys/stat.h>  

#ifdef WIN32
#include <iostream> 
#include <WINDOWS.H>  
#else
#include <dirent.h>
#include <unistd.h>
#endif

namespace bubi{


	MsgProcessor::MsgProcessor(){
		
		rcv_message_lists_.clear();
		send_message_lists_.clear();
	}

	MsgProcessor::~MsgProcessor() {
	}

	bool MsgProcessor::Initialize() {
		bool bret = false;
		http_.Initialize("127.0.0.1");
		uint32_t test_input_ = 0;
		
			thread_ptr_ = new utils::Thread(this);
			if (!thread_ptr_->Start()) {
				printf("Initialize -- start thread failed");
				
			}
			bret = true;		
		return bret;
	}
	void MsgProcessor::Run(utils::Thread *thread) {
		while (thread->enabled()) {
			// process request message
			do {
				if (rcv_message_lists_.empty()) {
					utils::Sleep(1);
					continue;
				}
				std::string	msg;
				{
					utils::MutexGuard guard(rcv_message_lists_mutex_);
					msg = rcv_message_lists_.front();
				}
				if (!ProcessRcvMessages(msg)) {
					continue;
				}
				
				utils::MutexGuard guard(rcv_message_lists_mutex_);
				rcv_message_lists_.pop_front();
			} while (false);

			// process response message
			do {
				if (send_message_lists_.empty()) {
					utils::Sleep(1);
					continue;
				}
				std::string	msg;
				{
					utils::MutexGuard guard(send_message_lists_mutex_);
					msg = send_message_lists_.front();
				}
				if (!ProcessSendMessages(msg)) {
					continue;
					}
				{
					utils::MutexGuard guard(send_message_lists_mutex_);
					send_message_lists_.pop_front();
				}
				utils::Sleep(0);
			} while (false);

		}
	}

	bool MsgProcessor::Exit() {
		try {
			if (thread_ptr_)
			{
				thread_ptr_->JoinWithStop();
				delete thread_ptr_;
				thread_ptr_ = NULL;
			}

			//wait for current period to finish
			utils::Sleep(100);
			rcv_message_lists_.clear();
			send_message_lists_.clear();
			
		}
		catch (std::exception& e) {
			printf("Exit -- %s", e.what());
		}

		return true;
	}

	WebSocketServer::WebSocketServer(){

	}
	WebSocketServer::~WebSocketServer(){
		msg_processor_.Exit();		
	}


	bool WebSocketServer::Initialize(){

		last_time_ = 0;
		connet_clients_.clear();

		server_ptr_ = new server();
		server_ptr_->init_asio();
		server_ptr_->set_max_message_size(1048576);
		server_ptr_->set_open_handler(std::bind(&WebSocketServer::on_open, this, std::placeholders::_1));
		server_ptr_->set_close_handler(std::bind(&WebSocketServer::on_close, this, std::placeholders::_1));
		server_ptr_->set_message_handler(std::bind(&WebSocketServer::on_message, this, std::placeholders::_1, std::placeholders::_2));
		server_ptr_->set_interrupt_handler(std::bind(&WebSocketServer::on_error, this, std::placeholders::_1));
		server_ptr_->set_reuse_addr(true);
		server_ptr_->listen(19336);
		server_ptr_->start_accept();
		msg_processor_.server_ptr_ = server_ptr_;
		msg_processor_.Initialize();
		

		return Start();
	}
	bool WebSocketServer::Exit(){
		utils::MutexGuard guard(connet_clients_mutex_);

		std::string sreason;
		for (auto it = connet_clients_.begin(); it != connet_clients_.end(); it++) {
			std::string s;
			server_ptr_->close(it->second, websocketpp::close::status::normal, sreason);
		}

		if (server_ptr_) {
			server_ptr_->stop();
			delete server_ptr_;
			server_ptr_ = nullptr;
		}
		return true;
	}
	void WebSocketServer::Run(){
		server_ptr_->run();
	}

	//new connet client
	void WebSocketServer::on_open(connection_hdl hdl){
		msg_processor_.SetConnectionHandler(hdl);
	}

	//client close
	void WebSocketServer::on_close(connection_hdl hdl){
		utils::MutexGuard guard(connet_clients_mutex_);

		std::string endpoint_key = server_ptr_->get_con_from_hdl(hdl)->get_remote_endpoint();
		connet_clients_.erase(endpoint_key);
	}
	//client message
	void WebSocketServer::on_message(connection_hdl hdl, server::message_ptr msg){
		utils::MutexGuard guard(connet_clients_mutex_);
		std::string endpoint_key;
		endpoint_key = server_ptr_->get_con_from_hdl(hdl)->get_remote_endpoint();

		std::string data = msg->get_payload();

		utils::MutexGuard guard2(msg_processor_.rcv_message_lists_mutex_);
		msg_processor_.rcv_message_lists_.push_back(data);
		
		connet_clients_[endpoint_key] = hdl;
	}

	void WebSocketServer::on_error(connection_hdl hdl){
		utils::MutexGuard guard(connet_clients_mutex_);

		std::string endpoint_key = server_ptr_->get_con_from_hdl(hdl)->get_remote_endpoint();
		connet_clients_.erase(endpoint_key);
	}

	//send to client
	void WebSocketServer::Send(std::string &data){
		utils::MutexGuard guard(connet_clients_mutex_);
		for (auto i : connet_clients_)
		{
			server_ptr_->send(i.second, data, websocketpp::frame::opcode::value::text);
		}
	}
	

	bool MsgProcessor::ProcessSendMessages(const std::string& msg)
	{
		bool bret = false;
		try {
			do {
				//first to check if need conversion
				Json::Value content;
				content.fromString(msg);
				if (content.isMember("parameter") || content.isMember("result"))
				{
					Json::Value parameter_or_result = content.isMember("parameter") ? content["parameter"] : content["result"];
					if (parameter_or_result.isMember("session_id"))
					{
						if (parameter_or_result["session_id"].asString() == "random_key")
						{
							parameter_or_result["session_id"] = random_key_;
						}
						if (content.isMember("parameter"))
							content["parameter"] = parameter_or_result;
						else
							content["result"] = parameter_or_result;
					}
					server_ptr_->send(connection_hdl_, content.toFastString(), websocketpp::frame::opcode::text);
					
				}
				else
				{
					//it is the abnormal message for abnormal test
					server_ptr_->send(connection_hdl_,msg, websocketpp::frame::opcode::text);
				}
				bret = true;
			} while (false);
		}
		catch (std::exception&) {
			//printf("ProcessResponseMessages -- server has disconnected\n");
		}
		return bret;

	}
	void MsgProcessor::SendRequestMessage(const std::string& method, const bool& request, const Json::Value& parameter) 
	{
		do {
			Json::Value message;
			message["method"] = method;
			message["request"] = request;
			message["parameter"] = parameter;
			utils::MutexGuard guard(send_message_lists_mutex_);
			send_message_lists_.push_back(message.toFastString());
		} while (false);
	}

	void MsgProcessor::SendResponseMessage(const std::string& method, const bool& request, const int& error_code, const Json::Value& result) {
		do {
			Json::Value message;
			message["method"] = method;
			message["request"] = request;
			message["error_code"] = error_code;
			message["result"] = result;
			utils::MutexGuard guard(send_message_lists_mutex_);
			send_message_lists_.push_back(message.toFastString());
		} while (false);
	}
	void MsgProcessor::DetermineResponse(std::string method)
	{
		Json::Value result;
		int errcode;

		if (current_condition_&GENERAL_CASE_RESPONSE_BAD_SESSION_ID)
			result["session_id"] = "bad_session_id";
		else
			result["session_id"] = random_key_;		

		switch (current_condition_ & 0x3ff)
		{
		case GENERAL_CASE_RESPONSE_ERRCODE_0:
			errcode = 0;
			break;
		case GENERAL_CASE_RESPONSE_ERRCODE_14:
			errcode = 14;
			break;
		case GENERAL_CASE_RESPONSE_ERRCODE_21:
			errcode = 21;
			break;
		case GENERAL_CASE_RESPONSE_ERRCODE_20:
			errcode = 20;
			break;
		case GENERAL_CASE_RESPONSE_ERRCODE_22:
			errcode = 22;
			break;
		case GENERAL_CASE_RESPONSE_ERRCODE_MAX:
			errcode = 99999;
			break;
		case GENERAL_CASE_RESPONSE_ERRCODE_MINUS:
			errcode = -1;
			break;
		case GENERAL_CASE_RESPONSE_ERRCODE_UNDEF:
			errcode = 343543;
			break;
		default:
			errcode = 0;
		}
		SendResponseMessage(method, false, errcode, result);
	
	}
	//no matter it is a request or response
	bool MsgProcessor::ProcessRcvMessages(const std::string& msg)
	{
		Json::Value receive;
		receive.fromString(msg);
		if (receive["method"].asString() == "hello")
		{			
			//check the content
			if (CheckHello(msg))
				test_output_ |= HELLO_VALID;
			else
				test_output_ &= ~HELLO_VALID;
			if (!(test_input_&HELLO_RESP))
			{
				//dont response to hello
				return false;
			}
			Json::Value threshold;

			if (test_warning&WARNING_CPU_HIGH)
				threshold["cpu"] = 100;
			else if (test_warning&WARNING_CUP_LOW)
				threshold["cpu"] = 0;
			else
				threshold["cpu"] = 100;

			if (test_warning&WARNING_DISK_HIGH)
				threshold["disk"] = 100;
			else if (test_warning&WARNING_DISK_LOW)
				threshold["disk"] = 0;
			else
				threshold["disk"] = 100;

			if (test_warning&WARNING_MEMORY_HIGH)
				threshold["memory"] = 100;
			else if (test_warning&WARNING_MEMORY_LOW)
				threshold["memory"] = 0;
			else
				threshold["memory"] = 100;

			if (test_warning&WARNING_BUBI_CRACK_HIGH)
				threshold["bubi_crack"] = 100;
			else if (test_warning&WARNING_BUBI_CRACK_LOW)
				threshold["bubi_crack"] = 0;
			else
				threshold["bubi_crack"] = 100;

			if (test_warning&WARNING_BUBI_ATTACK_TIME_HIGH)
				threshold["bubi_attack_time"] = 100;
			else if (test_warning&WARNING_BUBI_ATTACK_TIME_LOW)
				threshold["bubi_attack_time"] = 0;
			else
				threshold["bubi_attack_time"] = 100;

			if (test_warning&WARNING_BUBI_ATTACK_CONT_HIGH)
				threshold["bubi_attack_counts"] = 100;
			else if (test_warning&WARNING_BUBI_ATTACK_CONT_LOW)
				threshold["bubi_attack_counts"] = 0;
			else
				threshold["bubi_attack_counts"] = 100;

			if (test_warning&WARNING_BUBI_CRACK_HIGH)
				threshold["bubi_crack"] = 100;
			else if (test_warning&WARNING_BUBI_CRACK_LOW)
				threshold["bubi_crack"] = 0;
			else
				threshold["bubi_crack"] = 100;
			
			threshold["consensus"] = 100;
			
			//result field
			Json::Value result;
			if (!(test_input_&HELLO_NO_THRESHOLD))
			result["threshold"] = threshold;
			
			result["connection_timout"] = "60";
			//calculate rand_id_md
			random_key_ = generateRandom();
			std::string md_unsign = current_monitor_id_ + random_key_;
			if (test_input_&HELLO_MD5)
				result["rand_id_md"] = utils::MD5::GenerateMD5((unsigned char*)md_unsign.c_str(), md_unsign.length());
			else
				result["rand_id_md"] = utils::MD5::GenerateMD5((unsigned char*)random_key_.c_str(), random_key_.length());

			if (!(test_input_&HELLO_NO_RANDOMKEY))
			result["random_key"] = random_key_;

			result["version"] = 1;

			if (test_input_&HELLO_ERRCODE_2)
				SendResponseMessage("hello", false, 2, result);
			else if (test_input_&HELLO_ERRCODE_16)
				SendResponseMessage("hello", false, 16, result);
			else if (test_input_&HELLO_ERRCODE_80)
				SendResponseMessage("hello", false, 80, result);
			else
				SendResponseMessage("hello", false, 0, result);			
		}
		else if (receive["method"].asString() == "register")
		{
			//check the content
			if (CheckReg(msg))
				test_output_ |= REG_VALID;
			else
				test_output_ &= ~REG_VALID;

			if (!(test_input_&REG_RESP))
			{
				//dont response to register
				return false;
			}
			//get session id
			Json::Value& parameter = receive["parameter"];
			std::string session_id;
			if (test_input_&REG_NORMAL)
				session_id = parameter["session_id"].asString();
			else
				session_id = "badsession";
			//result field
			Json::Value result;
			result["session_id"] = session_id;
			result["connection_timout"] = "30";
			if (test_input_&REG_ERRCODE_10)
				SendResponseMessage("register", false, 10, result);	
			else if (test_input_&REG_ERRCODE_1345)
				SendResponseMessage("register", false, 1345, result);
			else
				SendResponseMessage("register", false, 0, result);
		}
		else if (receive["method"].asString() == "heartbeat")
		{
			//check the content
			if (CheckHB(msg))
				test_output_ |= HB_VALID;
			else
				test_output_ &= ~HB_VALID;

			if (!(test_input_&HB_RESP))
			{
				//dont response to heartbeat
				return false;
			}
			//get session id
			Json::Value& parameter = receive["parameter"];
			std::string session_id;
			if (test_input_&HB_NORMAL)
				session_id = parameter["session_id"].asString();
			else
				session_id = "badsession";
			
			//result field
			Json::Value result;
			result["session_id"] = session_id;
			result["connection_timout"] = "60";
			if (test_input_&HB_ERRCODE_777)
				SendResponseMessage("heartbeat",false,777,result);
			else
				SendResponseMessage("heartbeat", false, 0, result);

		}
		else if (receive["method"].asString() == "logout")
		{
			if (CheckLogout(msg))
				test_output_ |= LOGOUT_VALID;
			else
				test_output_ &= ~LOGOUT_VALID;
		}
		else if (receive["method"].asString() == "warning")
		{
			//result field
			Json::Value result;
			result["session_id"] = random_key_;			
			SendResponseMessage("warning", false, 0, result);
		}
		else if (receive["method"].asString() == "bubi")
		{
			if (current_request_test_ != BUBI)
				return true;
			if (CheckBubi(msg))
			request_test_result_ = true;
			
			DetermineResponse("bubi");		
		}
		else if (receive["method"].asString() == "system")
		{
			if (current_request_test_ != SYSTEM)
				return true;
			if (CheckSystem(msg))
				request_test_result_ = true;
			DetermineResponse("system");
		}
		else if (receive["method"].asString() == "ledger")
		{
			if (current_request_test_ != LEDGER)
				return true;
			if (CheckLedger(msg))
				request_test_result_ = true;
			DetermineResponse("ledger");
		}
		else if (receive["method"].asString() == "account_exception")
		{
			if (current_request_test_ != ACCTEXCP)
				return true;
			if (CheckAcctExcp(msg))
				request_test_result_ = true;
			DetermineResponse("account_exception");
		}
		else if (receive["method"].asString() == "error")
		{
			if (CheckError(msg))
				test_output_ |= ERROR_VALID;
			else
				test_output_ &= ~ERROR_VALID;
		}
		else if (receive["method"].asString() == "upgrade")
		{
			if (current_request_test_ != UPGRADE)
				return true;
			if (CheckUpgrade(msg))
				request_test_result_ = true;
			DetermineResponse("upgrade");
		}
		else if (receive["method"].asString() == "set_configure")
		{
			if (current_request_test_ != SETCONFG)
				return true;
			if (CheckSetconfig(msg))
				request_test_result_ = true;
			DetermineResponse("set_configure");
		}
		else if (receive["method"].asString() == "get_configure")
		{
			if (current_request_test_ != GETCONFG)
				return true;
			if (CheckGetconfig(msg))
				request_test_result_ = true;
			DetermineResponse("get_configure");
		}		
		return true;
	}
	//check logout content
	bool MsgProcessor::CheckLogout(const std::string& msg)
	{
		Json::Value receive;
		receive.fromString(msg);

		Json::Value parameter = receive["result"];

		if (parameter["session_id"] != random_key_)
		{
			//id error
			return false;
		}
		if (receive["request"].asString() != "false")
			return false;
		if (receive["err_code"]!= 0)
			return false;
		return true;

	}
	//check request content
	bool MsgProcessor::CheckHello(const std::string& msg)
	{
		bool flag(false);

		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value parameter = receive["parameter"];

#ifdef WIN32
		if (parameter["id_md"] == utils::MD5::GenerateMD5((unsigned char*)monitor_id_.c_str(), monitor_id_.length()))
		{
			//id error
			current_monitor_id_ = monitor_id_;
			flag = true;
		}
#else
		if (parameter["id_md"] == utils::MD5::GenerateMD5((unsigned char*)monitor_id_1.c_str(), monitor_id_1.length()))
		{
			//id error
			current_monitor_id_= monitor_id_1;
			flag = true;
		}
		if (parameter["id_md"] == utils::MD5::GenerateMD5((unsigned char*)monitor_id_2.c_str(), monitor_id_2.length()))
		{
			//id error
			current_monitor_id_ = monitor_id_2;
			flag = true;
		}
#endif
		EXPECT_TRUE(flag)<<"hello md5 fail\n";
		if (!flag)
			ret =  false;
		EXPECT_STREQ("true", receive["request"].asString().c_str())<<"hello request field is not true\n";
		if (receive["request"].asString() != "true")
			ret =  false;
		return ret;
	}
	bool MsgProcessor::CheckReg(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value parameter = receive["parameter"];

		EXPECT_STREQ(random_key_.c_str(), parameter["session_id"].asString().c_str()) << "reg request with bad session id\n";
		if (parameter["session_id"].asString() != random_key_)
		{
			//session id error
			ret = false;
		}
		EXPECT_STREQ("true", receive["request"].asString().c_str()) << "reg request field is not true\n";
		if (receive["request"].asString() != "true")
			ret = false;
		return ret;
	}
	bool MsgProcessor::CheckHB(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value parameter = receive["parameter"];

		EXPECT_STREQ(random_key_.c_str(), parameter["session_id"].asString().c_str()) << "heartbeat request with bad session id\n";
		if (parameter["session_id"].asString() != random_key_)
		{
			//session id error
			ret = false;
		}
		if (receive["request"].asString() != "true")
			ret = false;
		return ret;

	}
	bool MsgProcessor::CheckLedger(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);
		
		Json::Value result = receive["result"];
		
		Json::Value result_from_bubi = latest_ledger[0]["result"];
		int seq = result["ledger_seq"].asInt();
	

		switch (current_condition_&(~0x3ff))
		{
			case LEDGER_LATEST_20_LEDGER:
				EXPECT_EQ(receive["error_code"].asInt(), 0);
				{
					Json::Value blocks = result["blocks"];
					for (int k = 0; k < 20; ++k)
					{
						result_from_bubi = latest_ledger[k]["result"];
						EXPECT_EQ(blocks[k]["ledger_seq"].asInt(), (result_from_bubi["ledger_seq"].asInt()));
						EXPECT_STREQ(blocks[k]["hash"].asCString(), result_from_bubi["hash"].asCString())<<"index = "<<k;
					}
				}
				
				break;
			case LEDGER_LATEST_LEDGER:
			case LEDGER_SEQ_BIGGER_THAN_LATEST:
			case LEDGER_NO_SEQ:
			case LEDGER_NO_NUM:
				EXPECT_EQ(receive["error_code"].asInt(), 0);
				{
					int k = 0;
					Json::Value blocks = result["blocks"];
					EXPECT_EQ(blocks[k]["ledger_seq"].asInt(), result_from_bubi["ledger_seq"].asInt());
					EXPECT_STREQ(blocks[k]["hash"].asCString(), result_from_bubi["hash"].asCString());
				}				
				break;
			case LEDGER_NUM_0:
			case LEDGER_SEQ_0:
			case LEDGER_NUM_MINUS:
			case LEDGER_SEQ_MINUS:

				EXPECT_EQ(receive["error_code"].asInt(), 14);
				EXPECT_FALSE(result.isMember("blocks"));
				break;
			
			case LEDGER_ONE_RANDOM_LEDGER:
				EXPECT_EQ(receive["error_code"].asInt(), 0);		
				break;
			
			default:
				break;
		}

		return ret;
	}
	bool MsgProcessor::CheckSystem(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value result = receive["result"];
		Json::Value property = result["property"];
#ifdef WIN32
		EXPECT_STREQ(property["host_name"].asCString(), "DESKTOP-ISOADM0");
#else
		EXPECT_STREQ(property["host_name"].asCString(), "bubi65");
#endif
		EXPECT_STREQ(property["os_bit"].asCString(), "64");
		ret = CheckCommonResponse(msg);
		return ret;
	}
	bool MsgProcessor::CheckAcctExcp(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value result = receive["result"];

		ret = CheckCommonResponse(msg);

		return ret;
	}
	bool MsgProcessor::CheckError(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value result = receive["result"];

		if (test_input_&ERR_ERRCODE_4)
		{
			EXPECT_EQ(receive["error_code"].asInt(), 4) << "system response error code is not 4";
			if (receive["error_code"].asInt() != 4)
				ret = false;
		}
		

		//here expect true,because a response is expected.
		if (receive["request"].asBool() != true)
			ret = false;

		//check result
		EXPECT_STREQ(random_key_.c_str(), result["session_id"].asString().c_str()) << "error response with bad session id\n";
		if (result["session_id"].asString() != random_key_)
			//session id error
			ret = false;
		return ret;
	}

	bool MsgProcessor::CheckUpgrade(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		int expected_errorcode;
		static int errcode_last_time;

		switch (current_condition_&(~0x3ff))
		{
		case UPGRADE_NO_FILENAME:
		case UPGRADE_NO_ITEM:			
		case UPGRADE_NO_MD5:
		case UPGRADE_NO_URL:
			expected_errorcode = 14;
			break;
		case UPGRADE_FILENAME_BUBI:
		case UPGRADE_FILENAME_BUBID:
		case UPGRADE_FILENAME_BUBIJSON:
		case UPGRADE_FILENAME_CACERTCRT:
		case UPGRADE_FILENAME_CACERTPEM:
		case UPGRADE_FILENAME_DH1024PEM:
		case UPGRADE_FILENAME_PRIVKEYPEM:
		case UPGRADE_FILENAME_SLAVE:
		case UPGRADE_FILENAME_SLAVED:
			expected_errorcode = 0;
			break;
		case UPGRADE_WRONG_FILENAME:
			expected_errorcode = 19;
			break;
		case UPGRADE_WRONG_MD5:
			expected_errorcode = 11;
			break;
		case UPGRADE_WRONG_URL:
			expected_errorcode = 10;
			break;
		case UPGRADE_UPGRADING:
			expected_errorcode = 12;
			break;

		}
		if ((current_condition_&(~0x3ff)) != UPGRADE_UPGRADING)
		{
			EXPECT_EQ(receive["error_code"].asInt(), expected_errorcode);
			if (receive["error_code"].asInt() == expected_errorcode)
				ret = true;
		}		
		else
		{
			if (errcode_last_time != 12)
				errcode_last_time = receive["error_code"].asInt();
			if (errcode_last_time == expected_errorcode)
				ret = true;
		}		
		return ret;
	}
	
	bool MsgProcessor::CheckGetconfig(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value result = receive["result"];


		ret = CheckCommonResponse(msg);

		return ret;
	}
	bool MsgProcessor::CheckSetconfig(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value result = receive["result"];

		ret = CheckCommonResponse(msg);

		return ret;
	}
	bool MsgProcessor::CheckBubi(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value result = receive["result"];

		ret = CheckCommonResponse(msg);	

		
#if 0
		if (result.isMember("api server"))
		{
			Json::Value apiserver = result["api server"];
			if (apiserver["web server"]["context"].asBool() != false)
				ret = false;
			if (apiserver["web server"]["name"].asString() != "web server")
				ret = false;
			if (apiserver["websocket server"]["listen_hash_count_all"].asInt() != 0)
				ret = false;
			if (apiserver["websocket server"]["listener_count"].asInt() != 0)
				ret =  false;
		}
		if (result.isMember("glue manager"))
		{
			Json::Value gluemanager = result["glue manager"];
			if (gluemanager["consensus.slot.ballot.envSize"].asInt() != 5)
				ret =  false;
		}
#endif
		return ret;

	}

	bool MsgProcessor::CheckCommonResponse(const std::string& msg)
	{
		bool ret(true);
		Json::Value receive;
		receive.fromString(msg);

		Json::Value result = receive["result"];

		std::string method = receive["method"].asString();


		EXPECT_EQ(receive["error_code"].asInt(), 0) << method.c_str() << " error code is not 0";
		if (receive["error_code"].asInt() != 0)
			ret = false;

		//check result
		EXPECT_STREQ(random_key_.c_str(), result["session_id"].asString().c_str()) << method.c_str() << "  response with bad session id\n";
		if (result["session_id"].asString() != random_key_)
			//session id error
			ret = false;

		return ret;
	}
	

	void WebSocketServer::Cleanoutput(void)
	{
		printf("clean all output!\n");
		msg_processor_.SetTestOutput(0);		
	}

	 void WebSocketServer::IncompleteRequestGenerator(bool rqst_or_resp,uint32_t missing_part,Json::Value& msg)
	{
		 if (rqst_or_resp == IS_REQUEST)
		 {
			 if (!(missing_part&NO_PARAMETER))
			 {
				 if (missing_part&EMPTY_PARAM)
					 msg["parameter"] = "";
				 else
				 {
					 Json::Value parameter;
					 if (!(missing_part&NO_SESSIONID))
					 {
						 if (missing_part&EMPTY_SESSIONID)
							parameter["session_id"] = "";
						 else
							parameter["session_id"] = "random_key";
					 }
					 
						
					 msg["parameter"] = parameter;

				 }
				

			 }
			 if (!(missing_part&NO_METHOD))
			 {
				 if (missing_part&EMPTY_METHOD)
					 msg["method"] = "";
				 else
					msg["method"] = "bubi";
			 }
			 if (!(missing_part&NO_REQUEST))
			 {
				 if (missing_part&EMPTY_REQUEST)
					 msg["request"] = "";
				 else
					msg["request"] = true;
			 }
			 
		 }
		 else
		 {
			 if (!(missing_part&NO_RESULT))
			 {
				 if (missing_part&EMPTY_RESULT)
					 msg["result"] = "";
				 else{
					 Json::Value result;
					 if (!(missing_part&NO_SESSIONID))
					 {
						 if (missing_part&EMPTY_SESSIONID)
							 result["session_id"] = "";
						 else
							 result["session_id"] = "random_key";
					 }
					 msg["result"] = result;						 
				 }				
			 }
			 if (!(missing_part&NO_ERRORCODE))
			 {
				 if (missing_part&EMPTY_ERRORCODE)
					 msg["error_code"] = "";
				 else
					 msg["error_code"] = 0;
			 }
			 if (!(missing_part&NO_METHOD))
			 {
				 if (missing_part&EMPTY_METHOD)
					 msg["method"] = "";
				 else
					msg["method"] = "register";
			 }
			 if (!(missing_part&NO_REQUEST))
			 {
				 if (missing_part&EMPTY_REQUEST)
					 msg["request"] = "";
				 else
					msg["request"] = false;
			 }

		 }	
		

	}
	 
	 void WebSocketServer::UpgradeLayout(Json::Value& param)
	 {
		 uint32_t current_condition = msg_processor_.GetCurrentCondition()&(~0x3ff);
		 Json::Value item;
		 if (current_condition&UPGRADE_NO_ITEM)
		 {
			 return;//no item, directly return
		 }
		 switch (current_condition)
		 {
		 case UPGRADE_NO_FILENAME:			 
			 break;
		 case UPGRADE_FILENAME_BUBI:
			 item["file_name"] = "bubi";
			 break;
		 case UPGRADE_FILENAME_BUBID:
			 item["file_name"] = "bubid";
			 break;
		 case UPGRADE_FILENAME_SLAVE:
			 item["file_name"] = "slave";
			 break;
		 case UPGRADE_FILENAME_SLAVED:
			 item["file_name"] = "bubid";
			 break;
		 case UPGRADE_FILENAME_BUBIJSON:
			 item["file_name"] = "bubi.json";
			 break;
		 case UPGRADE_FILENAME_DH1024PEM:
			 item["file_name"] = "dh1024.pem";
			 break;
		 case UPGRADE_FILENAME_CACERTCRT:
			 item["file_name"] = "cacert.crt";
			 break;
		 case UPGRADE_FILENAME_CACERTPEM:
			 item["file_name"] = "cacert.pem";
			 break;
		 case UPGRADE_FILENAME_PRIVKEYPEM:
			 item["file_name"] = "privkey.pem";
			 break;
		 case UPGRADE_WRONG_FILENAME:
			 item["file_name"] = "wrongname";
			 break;
		 default:
			 item["file_name"] = "bubi";
			 break;

		 }
		 if (!(current_condition&UPGRADE_NO_MD5))
		 {
			 if (current_condition&UPGRADE_WRONG_MD5)
			 {
				item["md5"] = "11111111111111111111111111";
			 }

			 else
				 item["md5"] = "2885cdb57f913ed832df4a0731bdc765";
		 }
		 
		 if (!(current_condition&UPGRADE_NO_URL))
		 {
			 if (!(current_condition&UPGRADE_WRONG_URL))
				 item["url"] = "https://ss0.bdstatic.com/5aV1bjqh_Q23odCf/static/superman/img/logo/bd_logo1_31bdc765.png";
			 else
				 item["url"] = "https://XXXXXXX";

		 }	

		 param["items"].append(item);		
	 }
	 void WebSocketServer::SetConfigLayout(Json::Value& param)
	 {
		 uint32_t current_condition = msg_processor_.GetCurrentCondition()&(~0x3ff);
		 switch (current_condition)
		 {
		 case SETCONFG_NORMAL:
			 param["config_file"] = "";
			 break;
		 case SETCONFG_NO_FILE:
			 break;
		 default:
			 break;
		 }	
		
	 }
	 void WebSocketServer::LedgerLayout(Json::Value& param)
	 {
		 //get the latest seq
		 bubi::HttpClient::RecvMessage rcv = msg_processor_.http_.http_request(bubi::HttpClient::HTTP_GET, "/getLedger", "");;
		
		 msg_processor_.latest_ledger[0].fromString(rcv.context);
		 Json::Value result = msg_processor_.latest_ledger[0]["result"];

		 uint32_t current_condition = msg_processor_.GetCurrentCondition()&(~0x3ff);

		 switch (current_condition)
		 {
		 case LEDGER_LATEST_LEDGER:
			 if (rcv.context.size() == 0)
			 {
				 param["seq"] = 10;
			 }
			 else
			 {
				 param["seq"] = result["ledger_seq"].asInt();
			 }
			
			 param["num"] = 1;
			 break;
		 case LEDGER_LATEST_20_LEDGER:
		 {
										 
			int current_height = result["ledger_seq"].asInt();
			current_height = 0 ? 10 : current_height;

			for (int i = 0; i <20; i++)
			{
				std::string param = "/getLedger?seq=";
				char t[128] = { 0 };
				sprintf(t, "%d", current_height - i);
				std::string seq = t;
				param = param + seq;
				rcv = msg_processor_.http_.http_request(bubi::HttpClient::HTTP_GET, param, "");;
				msg_processor_.latest_ledger[i].fromString(rcv.context);
				printf("send item is %s,receive %d \n", seq.c_str(), msg_processor_.latest_ledger[i]["result"]["ledger_seq"].asInt());

			}
			param["seq"] = result["ledger_seq"].asInt();
			param["num"] = 20;

		 }
			
			 break;
		 case LEDGER_NUM_0:
			
			 param["seq"] = (result["ledger_seq"].asInt() > 0 ? result["ledger_seq"].asInt() : 10);
			 param["num"] = 0;
			 break;
		 case LEDGER_SEQ_0:
			 param["seq"] = 0;
			 param["num"] = 1;
			 break;
		 case LEDGER_SEQ_BIGGER_THAN_LATEST:
			 param["seq"] = (result["ledger_seq"].asInt() > 0 ? result["ledger_seq"].asInt() : 1000000);
			 param["num"] = 1;
			 break;
		 case LEDGER_SEQ_MINUS:
			 param["seq"] = -1;
			 param["num"] = 1;
			 break;
		 case LEDGER_NUM_MINUS:
			 param["seq"] = (result["ledger_seq"].asInt() > 0 ? result["ledger_seq"].asInt() : 10);
			 param["num"] = -1;
			 break;
		 case LEDGER_ONE_RANDOM_LEDGER:
			 param["seq"] = (result["ledger_seq"].asInt() > 0 ? (result["ledger_seq"].asInt()/2) : 8);
			 param["num"] = 1;
			 break;
		 case LEDGER_NO_SEQ:
			 param["num"] = 1;
			 break;
		 case LEDGER_NO_NUM:
			 param["seq"] = (result["ledger_seq"].asInt() > 0 ? result["ledger_seq"].asInt() : 10);
		 }
	 }
	 void WebSocketServer::RequestTest()
	 {

		 if (connet_clients_.size() != 0)
			 connet_clients_.clear();
		 printf("set up a normal env!\n");
		 msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);

		 Cleanoutput();
		 Cleanerrrorcode();
		 msg_processor_.ResetRequestTestResult();

		 //wait sufficient time to get client connected
		 utils::Sleep(10000);

		 //send request
		 //parameter field
		 Json::Value parameter;
		 Json::Value item;
		 
		 if (msg_processor_.GetCurrentCondition()&GENERAL_CASE_REQUEST_BAD_SESSION_ID)
			 parameter["session_id"] = "badsession";
		 else
			 parameter["session_id"] = "random_key";

		 std::string method;

		 switch (msg_processor_.GetCurrentRequestTest())
		 {
		 case BUBI:
			 method = "bubi";
			 break;
		 case SYSTEM:
			 method = "system";
			 break;
		 case LEDGER:
			 method = "ledger";	
			 break;
		 case ACCTEXCP:
			 method = "account_exception";
			 break;
		 case UPGRADE:
			 method = "upgrade";			
			 break;
		 case GETCONFG:
			 method = "get_configure";
			 break;
		 case SETCONFG:
			 method = "set_configure";
			 break;
		 case UNDEF_METHOD:
			 method = "undefined_method";
			 break;
		 default:
			 break;
		 }
		 if (msg_processor_.GetCurrentRequestTest() == UPGRADE)
		 {
			 UpgradeLayout(parameter);
		 }
		 if (msg_processor_.GetCurrentRequestTest() == LEDGER)
		 {
			 LedgerLayout(parameter);
		 }
		 if (msg_processor_.GetCurrentRequestTest() == SETCONFG)
		 {
			SetConfigLayout(parameter);
		 }
		 msg_processor_.SendRequestMessage(method, true, parameter);
		 //wait sufficient time to get response
		 utils::Sleep(10000);
		 if (msg_processor_.GetCurrentRequestTest() == UNDEF_METHOD)
		 EXPECT_FALSE(msg_processor_.GetRequestTestResult());
		 else
		 EXPECT_TRUE(msg_processor_.GetRequestTestResult());

	 }
	
#ifdef WIN32
	bool WebSocketServer::IsLaterThan(WIN32_FIND_DATA wfd1, WIN32_FIND_DATA wfd2)
	{
		if (wfd1.ftLastWriteTime.dwHighDateTime > wfd2.ftLastWriteTime.dwHighDateTime)
			return true;
		if (wfd1.ftLastWriteTime.dwHighDateTime == wfd2.ftLastWriteTime.dwHighDateTime)
		{
			if (wfd1.ftLastWriteTime.dwLowDateTime > wfd2.ftLastWriteTime.dwLowDateTime)
				return true;			
		}
		return false;
	}
#endif
	
	bool WebSocketServer::RecordErrorLogLatestTime()
	{
		
		
#ifdef WIN32
		//find all file name under logpath
		std::string logpath("D:\\GYA\\SRC\\2.0.0.0_monitoragent\\build\\win32\\log\\monitor-err.log*");
		std::string logpath2("D:\\GYA\\SRC\\2.0.0.0_monitoragent\\build\\win32\\log\\");

		

		WIN32_FIND_DATA wfd;
		HANDLE hFind;		
		hFind = FindFirstFile(logpath.c_str(), &wfd);
		if ( hFind == INVALID_HANDLE_VALUE)
		{
			printf("no log file in log folder!\n");
			return false;
		}
			
		WIN32_FIND_DATA latest_log = wfd;
		
		do
		{
			latest_log = IsLaterThan(latest_log, wfd)?latest_log:wfd;

		} while (FindNextFile(hFind, &wfd));

		printf("latest_log is %s", latest_log.cFileName);
		
		logpath2 = logpath2 + latest_log.cFileName;
		

#else

		//get current path
		char buf[128] = { 0 };

		getcwd(buf, sizeof(buf));

		printf("current path is %s\n", buf);
		std::string logpath2 = buf;
		int loc = logpath2.size();
		logpath2.replace(loc-5,5,"env/1peer-with-slave/log");


		struct dirent * filename;    // return value for readdir()  
		struct dirent * latest_log = NULL;
		time_t latest_time = 0;
		
		DIR * dir = NULL;                   // return value for opendir()  

		dir = opendir( logpath2.c_str() );  
		
		if (dir == NULL)
		{
			printf("log path %s does not exist!\n",logpath2.c_str())	;
			return false;
		}
		std::string root = logpath2+"/";
		printf("root = %s \n",root.c_str());
		
		while ((filename = readdir(dir)) != NULL)
		{
			
			std::string str1 = "monitor-err";
			std::string filename1 = (std::string)filename->d_name;
			if(filename1.find(str1)==  std::string::npos)
			continue;
			
			logpath2 = root + filename1;
			
			struct stat statbuf;
			if (stat (logpath2.c_str(), &statbuf) == -1)
			{
				printf ("Get stat on %s Error %s\n", logpath2.c_str(), strerror (errno));
				return false;
			}
			if (S_ISDIR(statbuf.st_mode))
				return false;
			if (S_ISREG(statbuf.st_mode))
			{
				if(statbuf.st_mtime>latest_time)
				{
					latest_log = filename;
					latest_time = statbuf.st_mtime;
					printf("find a newer file,replace\n");
				}
			}			
		}
		if(latest_log!=NULL)
		{
			printf("latest_log is %s", latest_log->d_name);

			logpath2 = root + (std::string)latest_log->d_name;
		}
		else
		{
			printf("no file found in path %s", root.c_str());
		}

#endif



		FILE* pfile = fopen(logpath2.c_str(), "r");
		fseek(pfile, -1, SEEK_END);
		fgetpos(pfile, &pos_of_end_of_err_log);    
		printf("current_end  = %d\n",pos_of_end_of_err_log);

		
		char ch = fgetc(pfile);
		int i = 0;
		
		while (ch != '[')
		{

			i--;
			fseek(pfile, i, SEEK_END);
			ch = fgetc(pfile);
		}
		pre_err_log_timestamp_[0] = '[';
		i = 1;
		fpos_t temp;
		fgetpos(pfile, &temp);
		while (ch != ']')
		{
			ch = fgetc(pfile);
			pre_err_log_timestamp_[i++] = ch;	
					

		}
		printf("last time stamp is %s\n",pre_err_log_timestamp_);
		fclose(pfile);
		
		return true;
	}


	bool WebSocketServer::VerifyErrorLog(int err_code)
	{
		//find all file name under logpath	
		int i = 0;
#ifdef WIN32
		std::string logpath("D:\\GYA\\SRC\\2.0.0.0_monitoragent\\build\\win32\\log\\monitor-err.log*");
		std::string logpath2("D:\\GYA\\SRC\\2.0.0.0_monitoragent\\build\\win32\\log\\");
		WIN32_FIND_DATA wfd;  
		HANDLE hFind;
		
		hFind = FindFirstFile(logpath.c_str(), &wfd);
		if (hFind == INVALID_HANDLE_VALUE)
			return false;
		WIN32_FIND_DATA latest_log = wfd;
		WIN32_FIND_DATA second_latest_log = wfd;

		do
		{
			if (IsLaterThan(wfd, latest_log)==1)
			{
				second_latest_log = latest_log;
				latest_log = wfd;
				
			}
				
			else if (IsLaterThan(wfd, second_latest_log)==1)
				second_latest_log = wfd;
			else if (IsLaterThan(latest_log, second_latest_log) == 0)
				second_latest_log = wfd;

			
		} while (FindNextFile(hFind, &wfd));

		printf("latest_log is %s", latest_log.cFileName);
		printf("second_latest_log is %s", second_latest_log.cFileName);
	
		logpath2 = logpath2+latest_log.cFileName;

#else

		//get current path
		char buf[128] = { 0 };

		getcwd(buf, sizeof(buf));


		printf("current path is %s\n", buf);
		std::string logpath2 = buf;
		int loc = logpath2.size();
		logpath2.replace(loc-5,5,"env/1peer-with-slave/log");

		struct dirent * filename;    // return value for readdir()  
		struct dirent * latest_log;
		time_t latest_time = 0;

		

		DIR * dir = NULL;                   // return value for opendir()  


		dir = opendir( logpath2.c_str() );  
		
		if (dir == NULL)
		{
			printf("log path %s does not exist!\n",logpath2.c_str())	;
			return false;
		}

		std::string root = logpath2+"/";
		printf("root = %s \n",root.c_str());
		
		while ((filename = readdir(dir)) != NULL)
		{
			
			std::string str1 = "monitor-err";
			std::string filename1 = (std::string)filename->d_name;
			if(filename1.find(str1)==  std::string::npos)
			continue;
			
			logpath2 = root + filename1;
			
			struct stat statbuf;
			if (stat (logpath2.c_str(), &statbuf) == -1)
			{

				printf ("Get stat on %s Error %s\n", logpath2.c_str(), strerror (errno));

				return false;

			}

			if (S_ISDIR(statbuf.st_mode))

				return false;

			if (S_ISREG(statbuf.st_mode))

			{

				if(statbuf.st_mtime>latest_time)
				{
					latest_log = filename;
					latest_time = statbuf.st_mtime;
					printf("find a newer file,replace\n");
				}

			}			

		}

		printf("latest_log is %s\n", latest_log->d_name);

		logpath2 = root + (std::string)latest_log->d_name;


#endif




		FILE* pfile = fopen(logpath2.c_str(),"r");

		char actual_err_log_timestamp[40] = { 0 };
		
		if (!fsetpos(pfile, &pos_of_end_of_err_log))
		{
			char ch = fgetc(pfile);
			int i = 0;
			while (ch != '[')
			{		
				i++;
#ifdef WIN32
				fpos_t pos = pos_of_end_of_err_log - i;
#else
				fpos_t pos;
					pos.__pos = pos_of_end_of_err_log.__pos - i;
#endif
				fsetpos(pfile, &pos);
				ch = fgetc(pfile);
				
				//printf("ch = %c\n", ch);
				//utils::Sleep(3);
			}
			
			actual_err_log_timestamp[0] = '[';
			i = 1;
			fpos_t temp;
			fgetpos(pfile, &temp);
			while (ch != ']')
			{
				ch = fgetc(pfile);
				actual_err_log_timestamp[i++] = ch;

			}

		}
		
		//compare the actual one with the previous one
		bool flag = true;
		for (int i = 0; i < 40; ++i)
		{
			if (actual_err_log_timestamp[i] != pre_err_log_timestamp_[i])
			{
				flag = false;
				break;
			}			

		}
		
		if (flag)
		{
			//start to read the content and compare
			fsetpos(pfile, &pos_of_end_of_err_log);
			char buffer_temp[1028] = {0};
			int i = fread(buffer_temp, 1, 1028, pfile);
			std::string a = buffer_temp;
			std::string target;
			switch (err_code)
			{
			case 0:
				target = "";
				break;
			case 1:
				target = "on_response_error -- configure content error";
				break;
			case 3:
				target = "on_response_error -- service signature error";
				break;
			case 4:
				target = "on_response_error -- method does not exist";
				break;
			case 6:
				target = "on_response_error -- system info error";
				break;
			case 8:
				target = "on_response_error -- bubi info failed";
				break;
			case 9:
				target = "on_response_error -- system user permission denied";
				break;
			case 10:
				target = "on_response_error -- file download failed";
				break;
			case 11:
				target = "on_response_error -- file md5 error";
				break;
			case 12:
				target = "on_response_error -- is upgrading";
				break;
			case 13:
				target = "on_response_error -- session id error";
				break;
			case 14:
				target = "on_response_error -- illegal parameter";
				break;
			case 17:
				target = "on_response_error -- logout failed";
				break;
			case 18:
				target = "on_response_error -- set configure file failed";
				break;
			case 19:
				target = "on_response_error -- upgrade a file is not this program";
				break;
			default:
				target = "on_response_error -- illegal error_code";//illegal error code
				break;

			}
			
			if (a.find(target) != std::string::npos)
			{
				printf("found error log!\n");
				return true;
			}			
		}
		
			//it means this is a new log,need to check it all and also the new added parts of the second latest log!

	printf("cannot found error log for error code %d!\n", err_code);
		return false;
	}

	//to generate a random value
	std::string MsgProcessor::generateRandom()
	{
		srand((int)time(0));
		uint64_t rad =  random(999999999);

		char t[24];
		sprintf(t, "%d", rad);
		std::string b = t;
		return b;		
	}

	//All test interface	

	void WebSocketServer::NormalResponseTest1()
	{
		printf("do nothing");
		printf("**Test Start**this is a test for normal condition!\n");
		if (connet_clients_.size() != 0)
			connet_clients_.clear();
		printf("set up to response hello-->register-->heartbeat requests normally then send a request to logout!\n");
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);
		Cleanoutput();

		//start test
		Initialize();

		//record the start time
		int64_t start_time = utils::Timestamp::HighResolution();

		bool flag(false);
		//wait for a connection
		while (utils::Timestamp::HighResolution() - start_time < 10000000)
		{
			if (connet_clients_.size() == 1)
			{
				flag = true;
				break;
			}
			utils::Sleep(1);
		}

		EXPECT_TRUE(flag);

		//wait sufficient time
		utils::Sleep(30000);

		//get the output
		uint32_t result = msg_processor_.GetTestOutput();

		EXPECT_EQ(result&HELLO_VALID, HELLO_VALID);
		EXPECT_EQ(result&REG_VALID, REG_VALID);
		EXPECT_EQ(result&HB_VALID, HB_VALID);
		EXPECT_EQ(connet_clients_.size(), 1);

		Json::Value parameter;
		parameter["session_id"] = "random_key";
		msg_processor_.SendRequestMessage("logout", true, parameter);

		//wait for the connect to drop
		//record the start time
		start_time = utils::Timestamp::HighResolution();

		//wait for a connection
		while (utils::Timestamp::HighResolution() - start_time < 10000000)
		{
			if (connet_clients_.size() == 0)
			{
				break;
			}
			utils::Sleep(1);
		}
		EXPECT_EQ(connet_clients_.size(), 0);
	}
	void WebSocketServer::NormalResponseTest()
	{
		printf("**Test Start**this is a test for normal condition!\n");
		if (connet_clients_.size() != 0)
			connet_clients_.clear();
		printf("set up to response hello-->register-->heartbeat requests normally then send a request to logout!\n");
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);
		Cleanoutput();

		//start test
		Initialize();

		//record the start time
		int64_t start_time = utils::Timestamp::HighResolution();

		bool flag(false);
		//wait for a connection
		while (utils::Timestamp::HighResolution() - start_time < 10000000)
		{
			if (connet_clients_.size() == 1)
			{
				flag = true;
				break;
			}
			utils::Sleep(1);
		}

		EXPECT_TRUE(flag);

		//wait sufficient time
		utils::Sleep(30000);

		//get the output
		uint32_t result = msg_processor_.GetTestOutput();
		
		EXPECT_EQ(result&HELLO_VALID, HELLO_VALID);
		EXPECT_EQ(result&REG_VALID, REG_VALID);
		EXPECT_EQ(result&HB_VALID, HB_VALID);
		EXPECT_EQ(connet_clients_.size(), 1);

		Json::Value parameter;
		parameter["session_id"] = "random_key";
		msg_processor_.SendRequestMessage("logout", true, parameter);

		//wait for the connect to drop
		//record the start time
		start_time = utils::Timestamp::HighResolution();

		//wait for a connection
		while (utils::Timestamp::HighResolution() - start_time < 10000000)
		{
			if (connet_clients_.size() == 0)
			{
				break;
			}
			utils::Sleep(1);
		}
		EXPECT_EQ(connet_clients_.size(), 0);
	}
	void WebSocketServer::BadHelloResponseTest()
	{
		printf("**Test Start**this is a test for testing response with err code 2 and 16 on hello request!\n");
		bool ret = true;
		if (connet_clients_.size() != 0)
			connet_clients_.clear();
		printf("set up to response err code 2 then response err code 16.\n");
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | HELLO_ERRCODE_2 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);
		
		//first logout the client to begin with hello
		//send a request to logout.
		//result field
		Json::Value parameter;
		parameter["session_id"] = "random_key";
		msg_processor_.SendRequestMessage("logout", true, parameter);

		//wait for the current connection to drop
		utils::Sleep(2000);

		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		//expect only hello is valid,register and heartbeat no valid request received
		EXPECT_EQ(msg_processor_.GetTestOutput(), HELLO_VALID);
		
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | HELLO_ERRCODE_16 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);


		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		//expect only hello is valid,register and heartbeat no valid request received
		EXPECT_EQ(msg_processor_.GetTestOutput(), HELLO_VALID);
		

		//set error code to an undefined one, regard as a good one???
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | HELLO_ERRCODE_80 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);


		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		//expect only hello is valid,register and heartbeat no valid request received
		EXPECT_EQ(msg_processor_.GetTestOutput(), HELLO_VALID );
		

		//abnormal hello, bad md5
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);

		
		msg_processor_.SendRequestMessage("logout", true, parameter);

		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		//expect only hello is valid,register and heartbeat no valid request received
		EXPECT_EQ(msg_processor_.GetTestOutput(), HELLO_VALID);

		//abnormal hello,no threshold
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP|HELLO_MD5|HELLO_NO_THRESHOLD | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);

		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		//expect only hello is valid,register and heartbeat no valid request received
		EXPECT_EQ(msg_processor_.GetTestOutput(), HELLO_VALID);

		//abnormal hello,no randomkey
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | HELLO_NO_RANDOMKEY | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);

		
		msg_processor_.SendRequestMessage("logout", true, parameter);
		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		//expect only hello is valid,register and heartbeat no valid request received
		EXPECT_EQ(msg_processor_.GetTestOutput(), HELLO_VALID);

		//normal hello,register response with error code 10
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5|REG_RESP | REG_NORMAL | REG_ERRCODE_10 | HB_RESP | HB_NORMAL);

	
		msg_processor_.SendRequestMessage("logout", true, parameter);
		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		//expect only hello is valid,register and heartbeat no valid request received
		EXPECT_EQ(msg_processor_.GetTestOutput(), HELLO_VALID|REG_VALID);


		//normal hello,register response with error code 1345
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL | REG_ERRCODE_1345| HB_RESP | HB_NORMAL);

		
		msg_processor_.SendRequestMessage("logout", true, parameter);
		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		//expect only hello is valid,register and heartbeat no valid request received
		EXPECT_EQ(msg_processor_.GetTestOutput(), HELLO_VALID | REG_VALID);

		//normal hello,register response with error code 1345
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL |HB_ERRCODE_777 | HB_RESP | HB_NORMAL);

		
		msg_processor_.SendRequestMessage("logout", true, parameter);
		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		//expect only hello is valid,register and heartbeat no valid request received
		EXPECT_EQ(msg_processor_.GetTestOutput(), HELLO_VALID | REG_VALID| HB_VALID);
		
	}
	void WebSocketServer::BadSessionIDTest()
	{
		printf("**Test Start**This is a test to verify if a request with bad session id send, it is discard and the system keeps normal !\n");
		printf("**Test Start**This is a test to verify if a response with bad session id send, it is discard and the system keeps normal !\n");
		bool ret = true;
		if (connet_clients_.size() != 0)
			connet_clients_.clear();
		msg_processor_.ResetTestInput();

		printf("make register response with bad session id!\n");
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | HB_RESP | HB_NORMAL);

		//result field
		Json::Value parameter;
		parameter["session_id"] = "random_key";
		msg_processor_.SendRequestMessage("logout", true, parameter);

		//clean output
		Cleanoutput();


		//wait sufficient time
		utils::Sleep(20000);
		EXPECT_EQ(msg_processor_.GetTestOutput(), (HELLO_VALID | REG_VALID));

		printf("make heart beat with bad session id!\n");
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL | HB_RESP);

		//clean output
		Cleanoutput();

		//wait sufficient time
		utils::Sleep(25000);

		EXPECT_EQ(msg_processor_.GetTestOutput(), (HELLO_VALID | REG_VALID | HB_VALID));		
		
	}
	void WebSocketServer::RequestBubiTest()
	{
		printf("**Test Start**this is a test to verify the response of request \"bubi\"!\n");
		uint32_t testconditions[] = { GENERAL_CASE_RESPONSE_ERRCODE_0, GENERAL_CASE_RESPONSE_ERRCODE_14, \
			GENERAL_CASE_RESPONSE_ERRCODE_21, GENERAL_CASE_RESPONSE_ERRCODE_22, GENERAL_CASE_RESPONSE_ERRCODE_MAX, \
			GENERAL_CASE_RESPONSE_ERRCODE_MINUS, GENERAL_CASE_RESPONSE_BAD_SESSION_ID };

		msg_processor_.SetCurrentRequestTest(BUBI);

		for (int i = 0; i < (sizeof(testconditions) / 4); i++)
		{
			msg_processor_.SetCurrentCondition(testconditions[i]);
			RequestTest();
		}
	}
	void WebSocketServer::RequestSystemTest()
	{
		printf("**Test Start**this is a test to verify the response of request \"system\"!\n");
		uint32_t testconditions[] = { 
			GENERAL_CASE_RESPONSE_ERRCODE_0, 
			GENERAL_CASE_RESPONSE_ERRCODE_14,
			GENERAL_CASE_RESPONSE_ERRCODE_20,
			GENERAL_CASE_RESPONSE_ERRCODE_21, 
			GENERAL_CASE_RESPONSE_ERRCODE_22, 
			GENERAL_CASE_RESPONSE_ERRCODE_MAX,
			GENERAL_CASE_RESPONSE_ERRCODE_MINUS, 
			GENERAL_CASE_RESPONSE_BAD_SESSION_ID			
		};

		msg_processor_.SetCurrentRequestTest(SYSTEM);

		for (int i = 0; i < (sizeof(testconditions) / 4); i++)
		{
			msg_processor_.SetCurrentCondition(testconditions[i]);
			RequestTest();
		}
	}
	void WebSocketServer::RequestLedgerTest()
	{
		
		printf("**Test Start**this is a test to verify the response of request \"ledger\"!\n");
		uint32_t testconditions[] = { 
			GENERAL_CASE_RESPONSE_ERRCODE_0|LEDGER_LATEST_LEDGER, 
			GENERAL_CASE_RESPONSE_ERRCODE_14|LEDGER_LATEST_20_LEDGER, 
			GENERAL_CASE_RESPONSE_ERRCODE_21|LEDGER_NUM_0, 
			GENERAL_CASE_RESPONSE_ERRCODE_22|LEDGER_NUM_MINUS,
			GENERAL_CASE_RESPONSE_ERRCODE_MAX|LEDGER_SEQ_0, 
			GENERAL_CASE_RESPONSE_ERRCODE_MINUS|LEDGER_SEQ_MINUS,
			GENERAL_CASE_RESPONSE_ERRCODE_20|LEDGER_ONE_RANDOM_LEDGER,
			GENERAL_CASE_RESPONSE_BAD_SESSION_ID|LEDGER_SEQ_BIGGER_THAN_LATEST,
			LEDGER_NO_NUM,
			LEDGER_NO_SEQ
		};

		

		msg_processor_.SetCurrentRequestTest(LEDGER);

		for (int i = 0; i < (sizeof(testconditions) / 4); i++)
		{
			msg_processor_.SetCurrentCondition(testconditions[i]);
			RequestTest();
		}

		
	}
	void WebSocketServer::RequestAccountExceptionTest()
	{
		printf("**Test Start**this is a test to verify the response of request \"account_exception\"!\n");
		uint32_t testconditions[] = { 
			GENERAL_CASE_RESPONSE_ERRCODE_0, 
			GENERAL_CASE_RESPONSE_ERRCODE_14,
			GENERAL_CASE_RESPONSE_ERRCODE_21, 
			GENERAL_CASE_RESPONSE_ERRCODE_22, 
			GENERAL_CASE_RESPONSE_ERRCODE_MAX,
			GENERAL_CASE_RESPONSE_ERRCODE_MINUS, 
			GENERAL_CASE_RESPONSE_BAD_SESSION_ID 
		};

		msg_processor_.SetCurrentRequestTest(ACCTEXCP);

		for (int i = 0; i < (sizeof(testconditions) / 4); i++)
		{
			msg_processor_.SetCurrentCondition(testconditions[i]);
			RequestTest();
		}
	}
	void WebSocketServer::RequestUpgradeTest()
	{
		printf("**Test Start**this is a test to verify the response of request \"upgrade\"!\n");
		
		uint32_t testconditions[] = { 
			GENERAL_CASE_RESPONSE_ERRCODE_0|UPGRADE_FILENAME_BUBI,
			GENERAL_CASE_RESPONSE_ERRCODE_14|UPGRADE_FILENAME_BUBID, 
			GENERAL_CASE_RESPONSE_ERRCODE_21|UPGRADE_FILENAME_BUBIJSON,
			GENERAL_CASE_RESPONSE_ERRCODE_22|UPGRADE_FILENAME_CACERTCRT, 
			GENERAL_CASE_RESPONSE_ERRCODE_MAX|UPGRADE_FILENAME_CACERTPEM, 
			GENERAL_CASE_RESPONSE_ERRCODE_MINUS|UPGRADE_FILENAME_DH1024PEM, 
			GENERAL_CASE_RESPONSE_BAD_SESSION_ID|UPGRADE_FILENAME_PRIVKEYPEM,
			UPGRADE_FILENAME_SLAVE,
			UPGRADE_FILENAME_SLAVED,
			UPGRADE_NO_FILENAME,
			UPGRADE_NO_ITEM,
			UPGRADE_NO_MD5,
			UPGRADE_NO_URL,
			UPGRADE_WRONG_FILENAME,
			UPGRADE_WRONG_MD5,
			UPGRADE_WRONG_URL 
		};

		msg_processor_.SetCurrentRequestTest(UPGRADE);

		for (int i = 0; i < (sizeof(testconditions) / 4); i++)
		{
			msg_processor_.SetCurrentCondition(testconditions[i]);
			RequestTest();
		}


	}
	void WebSocketServer::RequestSetConfigTest()
	{
		printf("**Test Start**this is a test to verify the response of request \"set_configure\"!\n");
		
		uint32_t testconditions[] = { 
			GENERAL_CASE_RESPONSE_ERRCODE_0|SETCONFG_NORMAL, 
			GENERAL_CASE_RESPONSE_ERRCODE_14|SETCONFG_NO_FILE, 
			GENERAL_CASE_RESPONSE_ERRCODE_21, 
			GENERAL_CASE_RESPONSE_ERRCODE_22, 
			GENERAL_CASE_RESPONSE_ERRCODE_MAX, 
			GENERAL_CASE_RESPONSE_ERRCODE_MINUS, 
			GENERAL_CASE_RESPONSE_BAD_SESSION_ID 
		};

		msg_processor_.SetCurrentRequestTest(SETCONFG);

		for (int i = 0; i < (sizeof(testconditions) / 4); i++)
		{
			msg_processor_.SetCurrentCondition(testconditions[i]);
			RequestTest();
		}
		
	}
	void WebSocketServer::RequestGetConfigTest()
	{
		printf("**Test Start**this is a test to verify the response of request \"get_configure\"!\n");
		uint32_t testconditions[] = { 
			GENERAL_CASE_RESPONSE_ERRCODE_0, 
			GENERAL_CASE_RESPONSE_ERRCODE_14,
			GENERAL_CASE_RESPONSE_ERRCODE_20,
			GENERAL_CASE_RESPONSE_ERRCODE_21, 
			GENERAL_CASE_RESPONSE_ERRCODE_22, 
			GENERAL_CASE_RESPONSE_ERRCODE_MAX, 
			GENERAL_CASE_RESPONSE_ERRCODE_MINUS, 
			GENERAL_CASE_RESPONSE_BAD_SESSION_ID 
		};

		msg_processor_.SetCurrentRequestTest(GETCONFG);

		for (int i = 0; i < (sizeof(testconditions) / 4); i++)
		{
			msg_processor_.SetCurrentCondition(testconditions[i]);
			RequestTest();
		}
	}
	void WebSocketServer::RequestUndefTest()
	{
		printf("**Test Start**this is a test to verify the response of an undefined request!\n");
		Cleanoutput();
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL|ERR_ERRCODE_4);
		//result field
		Json::Value parameter;
		parameter["session_id"] = "random_key";
		Cleanoutput();
		msg_processor_.SendRequestMessage("logout", true, parameter);

		
		utils::Sleep(12000);

		msg_processor_.SetCurrentRequestTest(UNDEF_METHOD);
		
		RequestTest();

		//wait sufficient time
		utils::Sleep(20000);

		//expect connected
		EXPECT_EQ(connet_clients_.size(), 1);		


		//result field
		msg_processor_.SendRequestMessage("logout", true, parameter);

		//wait for the current connect to drop
		Cleanoutput();
		utils::Sleep(12000);
		//send a response
		
		Json::Value result;
		result["session_id"] = "random_key";
			
		msg_processor_.SendResponseMessage("undef", false, 0, result );

		//wait sufficient time
		utils::Sleep(25000);

		//expect connected
		EXPECT_EQ(connet_clients_.size(), 1);
		
	}
	void WebSocketServer::RequestIncompleteTest()
	{
		printf("**Test Start**this is a test to verify the incomplete message does not influence the monitor!\n");
		if (connet_clients_.size() != 0)
			connet_clients_.clear();
		printf("set up a normal env!\n");
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);

		Cleanoutput();

		//wait sufficient time to get client connected
		utils::Sleep(15000);
		uint32_t testrequest[] = { NO_METHOD, NO_PARAMETER, NO_SESSIONID, NO_REQUEST,EMPTY_METHOD,EMPTY_REQUEST, EMPTY_SESSIONID,EMPTY_PARAM };
		uint32_t testresp[] = { NO_METHOD, NO_RESULT, NO_ERRORCODE, NO_SESSIONID, NO_REQUEST,EMPTY_METHOD, EMPTY_REQUEST, EMPTY_SESSIONID, EMPTY_RESULT,EMPTY_ERRORCODE };

		bool ret = true;

		for (int i = 0; i < sizeof(testrequest) / 4; i++)
		{
			Json::Value msg;
			IncompleteRequestGenerator(IS_REQUEST, testrequest[i], msg);
			{
				utils::MutexGuard guard(msg_processor_.send_message_lists_mutex_);
				msg_processor_.send_message_lists_.push_back(msg.toFastString());
			}
			utils::Sleep(15000);
			EXPECT_EQ(connet_clients_.size(), 1);			

		}

		for (int i = 0; i < sizeof(testresp) / 4; i++)
		{
			Json::Value msg;
			IncompleteRequestGenerator(IS_RESPONSE, testresp[i], msg);
			{
				utils::MutexGuard guard(msg_processor_.send_message_lists_mutex_);
				msg_processor_.send_message_lists_.push_back(msg.toFastString());
			}
			utils::Sleep(15000);
			EXPECT_EQ(connet_clients_.size(), 1);
		}

		//send a string which is not a json
		std::string badmsg = "this is not a json";
		{
			utils::MutexGuard guard(msg_processor_.send_message_lists_mutex_);
			msg_processor_.send_message_lists_.push_back(badmsg);
		}
		utils::Sleep(15000);
		EXPECT_EQ(connet_clients_.size(), 1);

		

	}
	void WebSocketServer::ResponseErrorTest()
	{
		printf("**Test Start**this is a test to verify the err log by sending all error code!\n");
		if (connet_clients_.size() != 0)
			connet_clients_.clear();
		printf("set up a normal env!\n");
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);

		Cleanoutput();

		//wait sufficient time to get client connected
		utils::Sleep(15000);

		//send error code response	

		//result field
		Json::Value result;
		result["session_id"] = "random_key";

		int errcode[] = {0, 1, 3, 4, 6,8, 9, 10, 11, 12, 13, 14, 17, 18, 19 ,90};
		bool ret = true;
		for (int i = 0; i < (sizeof(errcode)/sizeof(errcode[0])); i++)
		{
			RecordErrorLogLatestTime();
			msg_processor_.SendResponseMessage("error", false, errcode[i], result);
			utils::Sleep(1000);
			EXPECT_TRUE(VerifyErrorLog(errcode[i])) << "Verify error log on error code " <<errcode[i];
		}
		
	}
	void WebSocketServer::WarningTest()
	{
		printf("**Test Start**this is a test to verify the warning!\n");

		if (connet_clients_.size() != 0)
			connet_clients_.clear();
		printf("set up a normal env!\n");
		msg_processor_.ResetTestInput();
		msg_processor_.SetTestInput(HELLO_RESP | HELLO_MD5 | REG_RESP | REG_NORMAL | HB_RESP | HB_NORMAL);

		Cleanoutput();

		//uint32_t warning[] = { WARNING_CPU_HIGH, WARNING_CUP_LOW, WARNING_CPU_HIGH, \
		//					WARNING_MEMORY_HIGH, WARNING_MEMORY_LOW, WARNING_MEMORY_HIGH, \
		//					WARNING_DISK_HIGH, WARNING_DISK_LOW, WARNING_DISK_HIGH,\
		//					WARNING_BUBI_CRACK_HIGH, WARNING_BUBI_ATTACK_CONT_LOW, \
		//	WARNING_BUBI_CRACK_LOW, WARNING_BUBI_ATTACK_CONT_HIGH, WARNING_BUBI_ATTACK_CONT_LOW };
		
		uint32_t warning[] = { WARNING_CUP_LOW, WARNING_CPU_HIGH };
		
		for (int i = 0; i < (sizeof(warning) / sizeof(warning[0])); i++)
		{
			Json::Value parameter;
			parameter["session_id"] = "random_key";
			msg_processor_.SendRequestMessage("logout", true, parameter);
			Cleanoutput();
			msg_processor_.ResetTestWarning();
			msg_processor_.SetWarning(warning[i]);
			utils::Sleep(35000);
		}

	}

}//end of bubi


