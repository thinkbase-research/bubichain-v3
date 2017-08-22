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

#include "monitor_manager.h"
#include "monitor_network.h"
#include <monitor/configure.h>

namespace monitor {


	MonitorManager::MonitorManager() : monitor_network_(NULL), 
									   thread_ptr_ (NULL) {

	}

	MonitorManager::~MonitorManager() {
		if (thread_ptr_) {
			delete thread_ptr_;
		}
		if (monitor_network_) {
			delete monitor_network_;
		}
	}

	bool MonitorManager::Initialize(char *serial_num /*= NULL*/, bool cert_enabled /*= false*/) {
		if (serial_num != NULL) {
			serial_num_ = serial_num;
		}

		bubi::SslParameter ssl_parameter;
		ssl_parameter.enable_ = cert_enabled;
		if (cert_enabled) {
			const bubi::SSLConfigure& ssl_configure = monitor::Configure::Instance().monitor_configure_.ssl_configure_;
			std::string strHome = utils::File::GetBinHome();
			ssl_parameter.cert_password_ = ssl_configure.private_password_;
			ssl_parameter.chain_file_ = utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.chain_file_.c_str());
			ssl_parameter.private_key_file_ = utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.private_key_file_.c_str());
			ssl_parameter.tmp_dh_file_ = utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.dhparam_file_.c_str());
			ssl_parameter.verify_file_ = utils::String::Format("%s/%s", strHome.c_str(), ssl_configure.verify_file_.c_str());
		}
		monitor_network_ = new MonitorNetwork(ssl_parameter);
		if (!monitor_network_->Initialize()) {
			return false;
		}

		thread_ptr_ = new utils::Thread(this);
		if (!thread_ptr_->Start("monitor-manager")) {
			return false;
		}

		TimerNotify::RegisterModule(this);
		return true;
	}

	bool MonitorManager::Exit() {
		bool ret1 = false;
		bool ret2 = false;
		if (monitor_network_) {
			monitor_network_->Stop();
		}
		if (thread_ptr_) {
			ret1 = thread_ptr_->JoinWithStop();
		}
		if (monitor_network_) {
			ret2 = monitor_network_->Exit();
		}
		return ret1 && ret2;
	}

	void MonitorManager::Run(utils::Thread *thread) {
		const  MonitorConfigure &monitor_configure = Configure::Instance().monitor_configure_;
		utils::InetAddress listen_address_ = utils::InetAddress::Any();
		listen_address_.SetPort(monitor_configure.listen_port_);
		monitor_network_->Start(listen_address_);
		//connection_
	}

	void MonitorManager::OnSlowTimer(int64_t current_time) {

	}

}