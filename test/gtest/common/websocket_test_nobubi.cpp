#include <gtest/gtest.h>
#include "common/private_key.h"
//#include <openssl/ripemd.h>
//#include <utils/logger.h>
#include <utils/crypto.h>
#include <utils/strings.h>
#include "web_socket_server.h"


class WebsocketTestWithoutBubi : public testing::Test {
protected:
	static void SetUpTestCase() {
		//init operation
//		websocket_server = new bubi::WebSocketServer();
		//websocket_server->Initialize();
		
	}
	static void TearDownTestCase() {
		
		//end operation
		delete websocket_server1;
		websocket_server1 = NULL;
		
	}
	// Some expensive resource shared by all tests.
	static bubi::WebSocketServer *websocket_server1;
	
};

bubi::WebSocketServer* WebsocketTestWithoutBubi::websocket_server1 = new bubi::WebSocketServer();

//to test the monitoragent with normal response from websocket_server
TEST_F(WebsocketTestWithoutBubi, NormalResponse)
{
	websocket_server1->NormalResponseTest();
}

TEST_F(WebsocketTestWithoutBubi, Warning)
{
	websocket_server1->WarningTest();
}

//to test the monitoragent with a request "system"
TEST_F(WebsocketTestWithoutBubi, RequestSystem)
{
	websocket_server1->RequestSystemTest();
}

//to test the monitoragent with a request "ledger"

TEST_F(WebsocketTestWithoutBubi, RequestLedger)
{
	websocket_server1->RequestLedgerTest();
}

//to test the monitoragent with an undefined method,need fix monitor
TEST_F(WebsocketTestWithoutBubi, RequestUndef)
{
	websocket_server1->RequestUndefTest();
}

//to test the monitoragent with an incomplete request, need fix monitor
TEST_F(WebsocketTestWithoutBubi, RequestIncomplete)
{
	websocket_server1->RequestIncompleteTest();
}

TEST_F(WebsocketTestWithoutBubi, RequestUpgrade)
{
	websocket_server1->RequestUpgradeTest();
}

//to test the monitoragent with a request "bubi"
TEST_F(WebsocketTestWithoutBubi, RequestBubi)
{
	websocket_server1->RequestBubiTest();
}



//to test the monitoragent with a request "error"
TEST_F(WebsocketTestWithoutBubi, ResponseError)
{
	websocket_server1->ResponseErrorTest();
}

TEST_F(WebsocketTestWithoutBubi, BadHelloResponse)
{
	websocket_server1->BadHelloResponseTest();
}


TEST_F(WebsocketTestWithoutBubi, RequestSetConfig)
{
	websocket_server1->RequestSetConfigTest();
}

TEST_F(WebsocketTestWithoutBubi, RequestGetConfig)
{
	websocket_server1->RequestGetConfigTest();
}


//to test the monitoragent with response including bad session id from websocket_server

TEST_F(WebsocketTestWithoutBubi, BadSessionID)
{
	websocket_server1->BadSessionIDTest();
}

//to test the monitoragent with a request "account_exception"
TEST_F(WebsocketTestWithoutBubi, RequestAccountException)
{
	websocket_server1->RequestAccountExceptionTest();
}
