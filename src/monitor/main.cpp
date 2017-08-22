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
#include <common/daemon.h>
#include <proto/cpp/monitor.pb.h>
#include "monitor_manager.h"
#include "configure.h"

bool g_enable_ = true;

void RunLoop();
void SignalFunc(int32_t code);
void InstallSignal();

int main() {

	monitor::AlertStatus status;
	monitor::AlertState state;
	state.set_value(12341234);
	monitor::AlertState* bubi_state = status.add_alert_state();
	bubi_state->CopyFrom(state);
	printf("%lf\n", status.mutable_alert_state(0)->value());

	//utils::Thread::SetCurrentThreadName("monitor-thread");

	//utils::Daemon::InitInstance();
	//utils::net::Initialize();
	//utils::Timer::InitInstance();
	//monitor::Configure::InitInstance();
	//bubi::SlowTimer::InitInstance();
	//utils::Logger::InitInstance();
	//monitor::MonitorManager::InitInstance();

	//do {
	//	utils::BubiAtExit bubiAtExit;
	//	InstallSignal();

	//	srand((uint32_t)time(NULL));
	//	utils::Daemon &daemon = utils::Daemon::Instance();
	//	if (!g_enable_ || !daemon.Initialize((int32_t)2345))
	//	{
	//		LOG_STD_ERRNO("Initialize daemon failed", STD_ERR_CODE, STD_ERR_DESC);
	//		break;
	//	}
	//	bubiAtExit.Push(std::bind(&utils::Daemon::Exit, &daemon));
	//	LOG_INFO("Initialize daemon successful");

	//	monitor::Configure &config = monitor::Configure::Instance();
	//	std::string config_path = bubi::General::MONITOR_CONFIG_FILE;
	//	if (!utils::File::IsAbsolute(config_path)){
	//		config_path = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), config_path.c_str());
	//	}
	//	if (!config.Load(config_path)){
	//		LOG_STD_ERRNO("Load configure failed", STD_ERR_CODE, STD_ERR_DESC);
	//		break;
	//	}
	//	LOG_INFO("Load configure successful");

	//	std::string log_path = config.logger_configure_.path_;
	//	if (!utils::File::IsAbsolute(log_path)){
	//		log_path = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), log_path.c_str());
	//	}
	//	bubi::LoggerConfigure logger_config = monitor::Configure::Instance().logger_configure_;
	//	utils::Logger &logger = utils::Logger::Instance();
	//	logger.SetCapacity(logger_config.time_capacity_, logger_config.size_capacity_);
	//	logger.SetExpireDays(logger_config.expire_days_);
	//	if (!g_enable_ || !logger.Initialize((utils::LogDest)logger_config.dest_, (utils::LogLevel)logger_config.level_, log_path, true)){
	//		LOG_STD_ERR("Initialize logger failed");
	//		break;
	//	}
	//	bubiAtExit.Push(std::bind(&utils::Logger::Exit, &logger));
	//	LOG_INFO("Initialize logger successful");

	//	monitor::MonitorManager &monitor_manager = monitor::MonitorManager::Instance();
	//	if (!monitor_manager.Initialize()) {
	//		LOG_STD_ERR("Initialize monitor manager failed");
	//		break;
	//	}
	//	bubiAtExit.Push(std::bind(&monitor::MonitorManager::Exit, &monitor_manager));
	//	LOG_INFO("Initialize monitor manager successful");

	//	RunLoop();

	//	LOG_INFO("Process begin quit...");
	//} while (false);

	//bubi::SlowTimer::InitInstance();
	//monitor::MonitorManager::ExitInstance();
	//monitor::Configure::ExitInstance();
	//utils::Logger::ExitInstance();
	//utils::Daemon::ExitInstance();
}

void RunLoop() {
	int64_t check_module_interval = utils::MICRO_UNITS_PER_SEC;
	int64_t last_check_module = 0;
	while (g_enable_){
		int64_t current_time = utils::Timestamp::HighResolution();

		for (auto item : bubi::TimerNotify::notifys_){
			item->TimerWrapper(utils::Timestamp::HighResolution());
			if (item->IsExpire(utils::MICRO_UNITS_PER_SEC)){
				LOG_WARN("The timer(%s) execute time(" FMT_I64 " us) is expire than 1s", item->GetTimerName().c_str(), item->GetLastExecuteTime());
			}
		}

		utils::Timer::Instance().OnTimer(current_time);
		utils::Logger::Instance().CheckExpiredLog();

		if (current_time - last_check_module > check_module_interval){
			utils::WriteLockGuard guard(bubi::StatusModule::status_lock_);
			bubi::StatusModule::GetModulesStatus(*bubi::StatusModule::modules_status_);
			last_check_module = current_time;
		}

		utils::Sleep(1);
	}
}

void SignalFunc(int32_t code) {
	fprintf(stderr, "Get quit signal(%d)\n", code);
	g_enable_ = false;
}

void InstallSignal() {
	signal(SIGHUP, SignalFunc);
	signal(SIGQUIT, SignalFunc);
	signal(SIGINT, SignalFunc);
	signal(SIGTERM, SignalFunc);
#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
}