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

#ifndef MONITOR_CONFIGURE_H_
#define MONITOR_CONFIGURE_H_

#include <common/configure_base.h>

namespace monitor {
	class MonitorConfigure {
	public:
		MonitorConfigure();

		int32_t listen_port_;
		std::string id_;
		std::string server_address_;
		bool ssl_enable_;
		bubi::SSLConfigure ssl_configure_;
		bool Load(const Json::Value &value);
	};

	class Configure : public bubi::ConfigureBase, public utils::Singleton<Configure> {
	public:
		MonitorConfigure monitor_configure_;
		bubi::LoggerConfigure logger_configure_;

		bool LoadFromJson(const Json::Value &values);
	};
}

#endif