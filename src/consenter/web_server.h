#ifndef WEB_SERVER_H_
#define WEB_SERVER_H_

#include <3rd/http/server.hpp>
#include <common/general.h>
#include <common/storage.h>
#include <utils/singleton.h>
#include <proto/message.pb.h>
#include <utils/net.h>

namespace bubi {

	class WebServer :public utils::Singleton<bubi::WebServer>, public bubi::StatusModule
	{
		friend class utils::Singleton<bubi::WebServer>;
	public:
		WebServer();
		~WebServer();
	private:
		utils::AsyncIo *async_io_ptr_;
		http::server::server *server_ptr_;
		asio::ssl::context *context_;
		RationalDb *rational_db_;
		bool running;

		void FileNotFound(const http::server::request &request, std::string &reply);
		void Hello(const http::server::request &request, std::string &reply);
		void CreateAccount(const http::server::request &request, std::string &reply);
		void GetAccount(const http::server::request &request, std::string &reply);
		void GetConsensusInfo(const http::server::request &request, std::string &reply);
		void GetModulesStatus(const http::server::request &request, std::string &reply);
		void GetTransactionHistory(const http::server::request &request, std::string &reply);

		std::string GetCertPassword(std::size_t, asio::ssl::context_base::password_purpose purpose);

		void MultiQuery(const http::server::request &request, std::string &reply);
		void SubmitTransaction(const http::server::request &request, std::string &reply);
		void GetLedger(const http::server::request &request, std::string &reply);

	public:
		bool Initialize(WebServerConfigure &webserver_configure);
		bool Exit();
		void GetModuleStatus(Json::Value &data);
	};
}

#endif