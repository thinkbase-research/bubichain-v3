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

#include "configure.h"

namespace monitor {
	MonitorConfigure::MonitorConfigure() : listen_port_(4053) {
	}

	bool MonitorConfigure::Load(const Json::Value &value) {
		Configure::GetValue(value, "listen_port", listen_port_);
		Configure::GetValue(value, "id", id_);
		Configure::GetValue(value, "server_address", server_address_);
		Configure::GetValue(value, "ssl_enable", ssl_enable_);
		ssl_configure_.Load(value["ssl"]);

		return true;
	}

	bool Configure::LoadFromJson(const Json::Value &values) {
		monitor_configure_.Load(values["monitor"]);
		logger_configure_.Load(values["logger"]);

		return true;
	}
}