#include <gtest/gtest.h>
#include "common/web_socket_server.h"
//class FooEnvironment :public testing::Environment
//{
//public:
//	virtual void SetUp(){
//		//init operation
//		websocket_server_ = new bubi::WebSocketServer();
//		websocket_server_->Initialize();
//	}
//	virtual void TearDown(){
//		while (true)
//		{
//			utils::Sleep(1);
//		}
//		//end operation
//		delete websocket_server_;
//	}
//
//	bubi::WebSocketServer *websocket_server_;
//};

GTEST_API_ int main(int argc, char **argv)
{
	//testing::AddGlobalTestEnvironment(new FooEnvironment);
	testing::GTEST_FLAG(output) = "xml:gtest_result.xml";
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}