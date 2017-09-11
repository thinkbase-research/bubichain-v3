/*
Copyright Bubi Technologies Co., Ltd. 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <utils/headers.h>
#include <common/general.h>
#include <common/private_key.h>
#include <main/configure.h>

#include "web_server.h"

namespace bubi {
	void WebServer::UpdateLogLevel(const http::server::request &request, std::string &reply) {
		std::string levelreq = request.GetParamValue("level");
		utils::LogLevel loglevel = utils::LOG_LEVEL_ALL;
		std::string loglevel_info = "LOG_LEVEL_ALL";
		if (levelreq == "1") {
			loglevel = (utils::LogLevel)(utils::LOG_LEVEL_ALL & ~utils::LOG_LEVEL_TRACE);
			loglevel_info = "LOG_LEVEL_ALL & ~utils::LOG_LEVEL_TRACE";
		}

		utils::Logger::Instance().SetLogLevel(loglevel);
		reply = utils::String::Format("set log level to %s", loglevel_info.c_str());
	}
}