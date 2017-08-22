#ifndef HTTP_CLIENT
#define HTTP_CLIENT

#include <asio.hpp>
#include <iostream>
#include <istream>
#include <ostream>
#include <utils/strings.h>
#include <utils/utils.h>

namespace bubi
{
	class HttpClient
	{
	public:
		enum HTTP_REQUEST
		{
			HTTP_POST,
			HTTP_GET
		};

		struct RecvMessage{
			std::string http_version;
			unsigned int status_code;
			std::string context;
		};

		HttpClient();
		~HttpClient();

		bool Initialize(std::string address);

		RecvMessage http_request(HTTP_REQUEST sendtype, std::string path, std::string content);
	private:
		std::string ip_ ;
		unsigned short port_;
	};
}
#endif