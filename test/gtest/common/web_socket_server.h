#ifndef WEB_SOCKET_SERVER_H_
#define  WEB_SOCKET_SERVER_H_

#include <utils/thread.h>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <json/json.h>

#include<time.h>
#include "http_client.h"

//the configuration of test input
#define BIT(i) (((uint32_t)(1))<<(i))
#define HELLO_RESP				BIT(0)		//hello response exist
#define HELLO_MD5			BIT(1)		//hello response with right md5 code
#define REG_RESP				BIT(2)		//register response exist
#define REG_NORMAL				BIT(3)		//register response with right session id
#define REG_ERRCODE_10			BIT(16)		//register response with error code 10
#define REG_ERRCODE_1345		BIT(18)		//register response with error code 1345
#define HB_RESP					BIT(4)		//heartbeat response exist
#define HB_NORMAL				BIT(5)		//heartbeat response with right session id
#define HB_ERRCODE_777			BIT(19)		//heartbeat response with wrong error code
#define HELLO_ERRCODE_2			BIT(6)		//hello response with errcode 6
#define HELLO_ERRCODE_16		BIT(7)		//hello response with errcode 10
#define HELLO_ERRCODE_80		BIT(8)		//hello response with errcode 80 (undefine error code)

#define GETCONFG_ERRCODE_10		BIT(11)		//get_configure response with errcode 10
#define SETCONFG_ERRCODE_10		BIT(12)		//set_configure response with errcode 10
#define SETCONFG_NORMAL			BIT(22)		//set_configure request with config_file ffieldeld 
#define UPGRADE_ERRCODE_10		BIT(13)		//upgrade response with errcode 10
#define UPGRADE_ERRCODE_678		BIT(20)		//upgrade response with errcode 678
#define ERR_ERRCODE_4			BIT(21)		//err response with errorcode 4

#define HELLO_NO_THRESHOLD			BIT(14)		//hello response threshold exist
#define HELLO_NO_RANDOMKEY			BIT(15)		//hello response randomkey exist

#define HELLO_VALID				BIT(0)		//set to 1 if valid hello is received
#define REG_VALID				BIT(1)		//set to 1 if valid register is received
#define HB_VALID				BIT(2)		//set to 1 if valid heartbeat is received
#define LOGOUT_VALID			BIT(3)		//set to 1 if valid logout response is received

//to identify the request currently under test
#define BUBI							BIT(1)		//set to 1 if bubi request is under test
#define LEDGER							BIT(2)		//set to 1 if ledger request is under test
#define SYSTEM							BIT(3)		//set to 1 if system request is under test
#define ACCTEXCP						BIT(4)		//set to 1 if acctexcp request is under test
#define UPGRADE							BIT(5)		//set to 1 if upgrade request is under test
#define GETCONFG						BIT(6)		//set to 1 if getconfg request is under test
#define SETCONFG						BIT(7)		//set to 1 if setconfg request is under test

//general case for every request
//attaension£ºthese conditions are for responses, not request itself
#define GENERAL_CASE_RESPONSE_ERRCODE_MAX	BIT(1)
#define GENERAL_CASE_RESPONSE_ERRCODE_MINUS	BIT(2)
#define GENERAL_CASE_RESPONSE_ERRCODE_UNDEF	BIT(3)
#define GENERAL_CASE_RESPONSE_ERRCODE_0		BIT(4)
#define GENERAL_CASE_RESPONSE_ERRCODE_20		BIT(5)
#define GENERAL_CASE_RESPONSE_ERRCODE_22		BIT(6)
#define GENERAL_CASE_RESPONSE_ERRCODE_21		BIT(7)
#define GENERAL_CASE_RESPONSE_ERRCODE_14		BIT(8)
#define GENERAL_CASE_RESPONSE_BAD_SESSION_ID	BIT(9)

#define GENERAL_CASE_REQUEST_BAD_SESSION_ID		BIT(10)
//bubi request test condition
//NONE

//ledger request test condition
#define LEDGER_LATEST_LEDGER			BIT(11)
#define LEDGER_LATEST_20_LEDGER			BIT(12)
#define LEDGER_ONE_RANDOM_LEDGER		BIT(13)
#define LEDGER_SEQ_BIGGER_THAN_LATEST	BIT(14)
#define LEDGER_SEQ_0					BIT(15)
#define LEDGER_NUM_0					BIT(16)
#define LEDGER_SEQ_MINUS				BIT(17)
#define LEDGER_NUM_MINUS				BIT(18)
#define LEDGER_NO_NUM					BIT(19)
#define LEDGER_NO_SEQ					BIT(20)

//system request test condition
//none

//account exception test condition
//none

//upgrade exception test condition
#define UPGRADE_NO_ITEM						BIT(11)		//set to 1 if generating an upgrade rqst without item
#define UPGRADE_NO_FILENAME					BIT(12)		//set to 1 if generating an upgrade rqst without filename
#define UPGRADE_NO_URL						BIT(13)		//set to 1 if generating an upgrade rqst without URL
#define UPGRADE_NO_MD5						BIT(14)		//set to 1 if generating an upgrade rqst without MD5
#define UPGRADE_WRONG_MD5					BIT(15)		//set to 1 if generating an upgrade rqst with wrong MD5
#define UPGRADE_FILENAME_BUBI				BIT(16)		//set to 1 if generating an upgrade rqst with filename bubi
#define UPGRADE_FILENAME_BUBID				BIT(17)		//set to 1 if generating an upgrade rqst with filename bubid
#define UPGRADE_FILENAME_SLAVE				BIT(18)		//set to 1 if generating an upgrade rqst with filename slave
#define UPGRADE_FILENAME_SLAVED				BIT(19)		//set to 1 if generating an upgrade rqst with filename slaved
#define UPGRADE_FILENAME_BUBIJSON			BIT(20)		//set to 1 if generating an upgrade rqst with filename bubi.json
#define UPGRADE_FILENAME_CACERTPEM			BIT(21)		//set to 1 if generating an upgrade rqst with filename cacert.pem
#define UPGRADE_FILENAME_CACERTCRT			BIT(22)		//set to 1 if generating an upgrade rqst with filename cacert.crt
#define UPGRADE_FILENAME_PRIVKEYPEM			BIT(23)		//set to 1 if generating an upgrade rqst with filename privkey.pem
#define UPGRADE_FILENAME_DH1024PEM			BIT(24)		//set to 1 if generating an upgrade rqst with filename dh1024.pem
#define UPGRADE_WRONG_URL					BIT(25)		//set to 1 if generating an upgrade rqst with wrong url
#define UPGRADE_WRONG_FILENAME				BIT(26)		//set to 1 if generating an upgrade rqust with wrong filename
#define UPGRADE_UPGRADING					BIT(27)		//set to 1 if send upgrade rqst when upgrading

//setconfig test condition

#define SETCONFG_NO_FILE					BIT(11)

//getconfig test condition
//currently none

#define UNDEF_METHOD			BIT(31)		//set to 1 if to send a request with undefined method

#define ERROR_VALID				BIT(8)		//set to 1 if valid error response is received

//for incomplete test
#define NO_METHOD				BIT(1)		//set to 1 if generating a rqst or resp without method
#define NO_ERRORCODE			BIT(2)		//set to 1 if generating a resp without errorcode
#define NO_REQUEST				BIT(3)		//set to 1 if generating a rqst or resp without request
#define NO_PARAMETER			BIT(4)		//set to 1 if generating a rqst without parameter
#define NO_RESULT				BIT(5)		//set to 1 if generating a resp without result
#define NO_SESSIONID			BIT(6)		//set to 1 if generating a rqst or resp without session id
#define EMPTY_METHOD			BIT(7)		//set to 1 if generating a rqust or resp with an empty method
#define EMPTY_REQUEST			BIT(8)		//set to 1 if generating a rqust or resp with an empty request
#define EMPTY_ERRORCODE			BIT(9)		//set to 1 if generating a resp with an empty errorcode
#define EMPTY_PARAM				BIT(10)		//set to 1 if generating a rqust with an empty param
#define EMPTY_SESSIONID			BIT(11)		//set to 1 if generating a rqust or resp with an empty session id
#define EMPTY_RESULT			BIT(12)		//set to 1 if generating a resp with an empty result

//for upgrade test

#define IS_REQUEST				true
#define IS_RESPONSE				false

//for warning test
#define WARNING_CUP_LOW						BIT(0)
#define WARNING_CPU_HIGH					BIT(1)
#define WARNING_MEMORY_LOW					BIT(2)
#define WARNING_MEMORY_HIGH					BIT(3)
#define WARNING_DISK_LOW					BIT(4)
#define WARNING_DISK_HIGH					BIT(5)
#define WARNING_CONSENSUS_LOW				BIT(6)
#define WARNING_CONSENSUS_HIGH				BIT(7)
#define WARNING_BUBI_CRACK_LOW				BIT(8)
#define WARNING_BUBI_CRACK_HIGH				BIT(9)
#define WARNING_BUBI_ATTACK_TIME_LOW		BIT(10)
#define WARNING_BUBI_ATTACK_TIME_HIGH		BIT(11)
#define WARNING_BUBI_ATTACK_CONT_LOW		BIT(12)
#define WARNING_BUBI_ATTACK_CONT_HIGH		BIT(13)

#define random(x) (rand()%x)


using websocketpp::connection_hdl;
namespace bubi{
	typedef websocketpp::server<websocketpp::config::asio> server;
	
	//gya:define a processor to maintain sending and receiving lists and process the messages in it.
	class MsgProcessor : public utils::Runnable{

	public:
		MsgProcessor();
		~MsgProcessor();

		bool Initialize();
		bool Exit();
		void SetConnectionHandler(websocketpp::connection_hdl handler){ connection_hdl_ = handler; };
		std::list<std::string>		send_message_lists_;			// the queue of messages waiting for sending
		utils::Mutex				send_message_lists_mutex_;
		std::list<std::string>		rcv_message_lists_;		// the queue of rcv messages waiting for processing
		utils::Mutex				rcv_message_lists_mutex_;
		server* server_ptr_;
		
		//test interface
		void SetTestInput(uint32_t inputs){ test_input_ |= inputs; };
		void ResetTestInput(){ test_input_ = 0; };
		void SetWarning(uint32_t warning){ test_warning = warning; };
		uint32_t GetTestOutput(){ return test_output_; };
		
		uint32_t GetTestWarning(){ return test_warning; };
		void SetTestOutput(uint32_t output_init){ test_output_ = output_init; };
		
		void ResetTestWarning(){ test_warning = 0xff; };
		void SendRequestMessage(const std::string& method, const bool& request, const Json::Value& parameter);
		void SendResponseMessage(const std::string& method, const bool& request, const int& error_code, const Json::Value& result);

		//for request test
		void SetCurrentRequestTest(uint32_t current_test){ current_request_test_ = current_test; };
		void SetCurrentCondition(uint32_t current_condition){ current_condition_ = current_condition; };
		uint32_t GetCurrentRequestTest(void){ return current_request_test_; };
		uint32_t GetCurrentCondition(void){ return current_condition_; };
		uint32_t GetReturnedErrCode(){ return test_returned_errorcode; };
		void ResetErrCode(void){ test_returned_errorcode = 0xff; };
		void ResetRequestTestResult(void){ request_test_result_ = false; };
		bool GetRequestTestResult(void){ return request_test_result_; };

		HttpClient http_;
		Json::Value latest_ledger[20];
	private:
		void Run(utils::Thread *thread);
		//handler for receiving messages from client
		bool ProcessRcvMessages(const std::string& msg);
		bool ProcessSendMessages(const std::string& msg);
		void DetermineResponse(std::string method);
		//to setup if response the request normally
		volatile uint32_t test_input_;
		//to store the verify result for every request format
		volatile uint32_t test_output_;
		volatile uint32_t test_returned_errorcode;
		volatile uint32_t test_warning;
		
		volatile uint32_t current_request_test_;
		volatile uint32_t current_condition_;

		websocketpp::connection_hdl connection_hdl_;				// handle to connect client
		
		utils::Thread*	thread_ptr_;
		std::string current_monitor_id_;
		bool request_test_result_;

		
#ifdef WIN32
		const std::string monitor_id_ = "123123123123123";
		
#else
		const std::string monitor_id_1 = "bubiV8i9PstGLHj2qmMW9JKQQ2HpybnpoY2xme4a";
		const std::string monitor_id_2 = "bubiV8hxAjNUuwQJLdvYwFjRhQutzoTqz81RcWqh";
	
#endif
		std::string random_key_;
		std::string generateRandom();

		

		bool CheckHello(const std::string& msg);
		bool CheckReg(const std::string& msg);
		bool CheckHB(const std::string& msg);
		bool CheckLogout(const std::string& msg);
		bool CheckBubi(const std::string& msg);
		bool CheckSystem(const std::string& msg);
		bool CheckLedger(const std::string& msg);
		bool CheckAcctExcp(const std::string& msg);
		bool CheckError(const std::string& msg);
		bool CheckUpgrade(const std::string& msg);
		bool CheckSetconfig(const std::string& msg);
		bool CheckGetconfig(const std::string& msg);

		bool CheckCommonResponse(const std::string& msg);


	};//end gya


	
	class WebSocketServer :	public utils::Thread{

		

	public:
		WebSocketServer();
		~WebSocketServer();

		WebSocketServer(const WebSocketServer& s) = delete;

		bool Initialize();
		bool Exit();
		virtual void Run();

		void Send(std::string &data);


		//test interface
		void NormalResponseTest1();
		void NormalResponseTest();
		void BadHelloResponseTest();
		void BadSessionIDTest();
		void RequestBubiTest();
		void RequestSystemTest();
		void RequestLedgerTest();
		void RequestAccountExceptionTest();
		void RequestUpgradeTest();
		void RequestSetConfigTest();
		void RequestGetConfigTest();
		void RequestUndefTest();
		void RequestIncompleteTest();
		void ResponseErrorTest();
		void WarningTest();

		MsgProcessor msg_processor_;


	private:
		void on_open(connection_hdl hdl);
		void on_close(connection_hdl hdl);
		void on_message(connection_hdl hdl, server::message_ptr msg);
		void on_error(connection_hdl hdl);
		void delete_time_out();
		void RequestTest(void);

		void UpgradeLayout(Json::Value& param);
		void SetConfigLayout(Json::Value& param);
		void LedgerLayout(Json::Value& param);
		void RequestUpgradeTester(uint32_t checkmask, bool badsessionid, uint32_t expected_errorcode);
		void IncompleteRequestGenerator(bool rqst_or_resp, uint32_t missing_part, Json::Value& msg);
		void Cleanoutput(void);
		void Cleanerrrorcode(void){ msg_processor_.ResetErrCode(); };
		bool VerifyErrorLog(int err_code);
#ifdef WIN32
		bool IsLaterThan(WIN32_FIND_DATA wfd1, WIN32_FIND_DATA wfd2);
#endif
		bool RecordErrorLogLatestTime();

		utils::Mutex connet_clients_mutex_;
		std::map<std::string, connection_hdl> connet_clients_;

		int64_t last_time_;
		server *server_ptr_;
		

		char pre_err_log_timestamp_[40];
		fpos_t pos_of_end_of_err_log;

		
		
		
	};

}


#endif