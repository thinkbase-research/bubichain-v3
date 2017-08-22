#include <gtest/gtest.h>
#include "common/private_key.h"
//#include <openssl/ripemd.h>
//#include <utils/logger.h>
#include <utils/crypto.h>
#include <utils/strings.h>
#include "web_socket_server.h"


class WebsocketTest : public testing::Test {
protected:
	static void SetUpTestCase() {
			
	}
	static void TearDownTestCase() {
		
		//end operation
		delete websocket_server;
		websocket_server = NULL;
		
	}
	// Some expensive resource shared by all tests.
	static bubi::WebSocketServer *websocket_server;	
};

bubi::WebSocketServer* WebsocketTest::websocket_server = new bubi::WebSocketServer();

//to test the monitoragent with normal response from websocket_server
TEST_F(WebsocketTest, NormalResponse)
{
	websocket_server->NormalResponseTest();
}

TEST_F(WebsocketTest, BadHelloResponse)
{
	websocket_server->BadHelloResponseTest();
}

TEST_F(WebsocketTest, RequestGetConfig)
{
	websocket_server->RequestGetConfigTest();
}

//to test the monitoragent with an incomplete request, need fix monitor
TEST_F(WebsocketTest, RequestIncomplete)
{
	websocket_server->RequestIncompleteTest();
}

//to test the monitoragent with an undefined method,need fix monitor
TEST_F(WebsocketTest, RequestUndef)
{
	websocket_server->RequestUndefTest();
}


//to test the monitoragent with a request "system"
TEST_F(WebsocketTest, RequestSystem)
{
	websocket_server->RequestSystemTest();
}

//to test the monitoragent with a request "ledger"

TEST_F(WebsocketTest, RequestLedger)
{
	websocket_server->RequestLedgerTest();
}

//to test the monitoragent with response including bad session id from websocket_server

//to test the monitoragent with a request "bubi"
TEST_F(WebsocketTest, RequestBubi)
{
	websocket_server->RequestBubiTest();
}

//to test the monitoragent with a request "error"
TEST_F(WebsocketTest, ResponseError)
{
	websocket_server->ResponseErrorTest();
}

TEST_F(WebsocketTest, RequestSetConfig)
{
	websocket_server->RequestSetConfigTest();
}

TEST_F(WebsocketTest, Warning)
{
	websocket_server->WarningTest();
}

//to test the monitoragent with response including bad session id from websocket_server

TEST_F(WebsocketTest, BadSessionID)
{
	websocket_server->BadSessionIDTest();
}

//to test the monitoragent with a request "account_exception"
TEST_F(WebsocketTest, RequestAccountException)
{
	websocket_server->RequestAccountExceptionTest();
}


TEST_F(WebsocketTest, RequestUpgrade)
{
	websocket_server->RequestUpgradeTest();
}

