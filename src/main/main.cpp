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
#include <common/ca_manager.h>
#include <common/general.h>
#include <common/storage.h>
#include <common/private_key.h>
#include <common/argument.h>
#include <common/daemon.h>
#include <common/cfca.h>
#include <overlay/peer_manager.h>
#include <ledger/ledger_manager.h>
#include <consensus/consensus_manager.h>
#include <glue/glue_manager.h>
#include <api/web_server.h>
#include <api/websocket_server.h>
#include <ledger/contract_manager.h>
#include <monitor/monitor_manager.h>
#include "configure.h"

void RunLoop();
int main(int argc, char *argv[]){
	utils::Thread::SetCurrentThreadName("bubi-thread");

	utils::Daemon::InitInstance();
	utils::net::Initialize();
	utils::Timer::InitInstance();
	bubi::Configure::InitInstance();
	bubi::Storage::InitInstance();
	bubi::Global::InitInstance();
	cfca::CFCA::InitInstance();
	bubi::SlowTimer::InitInstance();
	utils::Logger::InitInstance();
	bubi::PeerManager::InitInstance();
	bubi::LedgerManager::InitInstance();
	bubi::ConsensusManager::InitInstance();
	bubi::GlueManager::InitInstance();
	bubi::WebSocketServer::InitInstance();
	bubi::WebServer::InitInstance();
	bubi::MonitorManager::InitInstance();
	//bubi::ContractManager::InitInstance();

	bubi::Argument arg;
	if (arg.Parse(argc, argv)){
		return 1;
	}

	do {
		utils::BubiAtExit bubiAtExit;
		bubi::InstallSignal();

		srand((uint32_t)time(NULL));
		bubi::StatusModule::modules_status_ = new Json::Value;
		utils::Daemon &daemon = utils::Daemon::Instance();
		if (!bubi::g_enable_ || !daemon.Initialize((int32_t)1234))
		{
			LOG_STD_ERRNO("Initialize daemon failed", STD_ERR_CODE, STD_ERR_DESC);
			break;
		}
		bubiAtExit.Push(std::bind(&utils::Daemon::Exit, &daemon));
		LOG_INFO("Initialize daemon successful");

		bubi::Configure &config = bubi::Configure::Instance();
		std::string config_path = bubi::General::CONFIG_FILE;
		if (!utils::File::IsAbsolute(config_path)){
			config_path = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), config_path.c_str());
		}

		if (!config.Load(config_path)){
			LOG_STD_ERRNO("Load configure failed", STD_ERR_CODE, STD_ERR_DESC);
			break;
		}
		LOG_INFO("Load configure successful");

		std::string log_path = config.logger_configure_.path_;
		if (!utils::File::IsAbsolute(log_path)){
			log_path = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), log_path.c_str());
		}
		bubi::LoggerConfigure logger_config = bubi::Configure::Instance().logger_configure_;
		utils::Logger &logger = utils::Logger::Instance();
		logger.SetCapacity(logger_config.time_capacity_, logger_config.size_capacity_);
		logger.SetExpireDays(logger_config.expire_days_);
		if (!bubi::g_enable_ || !logger.Initialize((utils::LogDest)logger_config.dest_, (utils::LogLevel)logger_config.level_, log_path, true)){
			LOG_STD_ERR("Initialize logger failed");
			break;
		}
		bubiAtExit.Push(std::bind(&utils::Logger::Exit, &logger));
		LOG_INFO("Initialize logger successful");

		// end run command
		
		// check certificate
		char serial[128] = { 0 };
		bool cert_enabled = false;

		bubi::CAManager ca;
		char out_msg[256] = { 0 };
		std::string node_private_key = config.p2p_configure_.node_private_key_;
		std::string verify_file = config.p2p_configure_.ssl_configure_.verify_file_;
		std::string chain_file = config.p2p_configure_.ssl_configure_.chain_file_;
		std::string private_key_file = config.p2p_configure_.ssl_configure_.private_key_file_;
		std::string private_password = config.p2p_configure_.ssl_configure_.private_password_;
		std::string domain = "";// config.p2p_configure_.ca_server_configure_.domain_;
		std::string path = "";//config.p2p_configure_.ca_server_configure_.path_;
		int port = 8080;//config.p2p_configure_.ca_server_configure_.port_;
		int iret = ca.CheckCertificate(node_private_key, verify_file, chain_file, private_key_file, private_password,
		domain, path, port, serial, cert_enabled, out_msg);
		if (0 == iret) {
			LOG_ERROR("check certificate failed, because %s", out_msg);
			break;
		}

		bubi::Storage &storage = bubi::Storage::Instance();
		LOG_INFO("keyvalue(%s),account(%s),ledger(%s)", 
			config.db_configure_.keyvalue_db_path_.c_str(),
			config.db_configure_.account_db_path_.c_str(),
			config.db_configure_.ledger_db_path_.c_str());

		if (!bubi::g_enable_ || !storage.Initialize(config.db_configure_, arg.drop_db_)) {
			LOG_ERROR("Initialize db failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::Storage::Exit, &storage));
		LOG_INFO("Initialize db successful");

		if (arg.drop_db_) {
			LOG_INFO("Drop db successfully");
			return 1;
		} 
		
		if ( arg.clear_consensus_status_ ){
			bubi::Pbft::ClearStatus();
			LOG_INFO("Clear consensus status successfully");
			return 1;
		}

		if (arg.create_hardfork_) {
			bubi::LedgerManager::CreateHardforkLedger();
			return 1;
		}

		bubi::Global &global = bubi::Global::Instance();
		if (!bubi::g_enable_ || !global.Initialize()){
			LOG_ERROR_ERRNO("Initialize global variable failed", STD_ERR_CODE, STD_ERR_DESC);
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::Global::Exit, &global));
		LOG_INFO("Initialize global variable successful");

		cfca::CFCA &cfca = cfca::CFCA::Instance();
		if (!bubi::g_enable_ || !cfca.Initialize()) {
			LOG_ERROR("Initialize cfca failed");
		}
		bubiAtExit.Push(std::bind(&cfca::CFCA::Exit, &cfca));
		LOG_INFO("Initialize cfca successful");

		//consensus manager must be initialized before ledger manager and glue manager
		bubi::ConsensusManager &consensus_manager = bubi::ConsensusManager::Instance();
		if (!bubi::g_enable_ || !consensus_manager.Initialize(bubi::Configure::Instance().validation_configure_)) {
			LOG_ERROR("Initialize consensus manager failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::ConsensusManager::Exit, &consensus_manager));
		LOG_INFO("Initialize consensus manager successful");

		bubi::LedgerManager &ledgermanger = bubi::LedgerManager::Instance();
		if (!bubi::g_enable_ || !ledgermanger.Initialize()) {
			LOG_ERROR("Initialize ledger manager failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::LedgerManager::Exit, &ledgermanger));
		LOG_INFO("Initialize ledger successful");

		bubi::GlueManager &glue = bubi::GlueManager::Instance();
		if (!bubi::g_enable_ || !glue.Initialize()){
			LOG_ERROR("Initialize glue manager failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::GlueManager::Exit, &glue));
		LOG_INFO("Initialize glue manager successful");

		bubi::PeerManager &p2p = bubi::PeerManager::Instance();
		if (!bubi::g_enable_ || !p2p.Initialize(serial, true)) {
			LOG_ERROR("Initialize peer network failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::PeerManager::Exit, &p2p));
		LOG_INFO("Initialize peer network successful");

		bubi::MonitorManager &monitor_manager = bubi::MonitorManager::Instance();
		if (!bubi::g_enable_ || !monitor_manager.Initialize()) {
			LOG_ERROR("Initialize monitor manager failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::MonitorManager::Exit, &monitor_manager));
		LOG_INFO("Initialize monitor manager successful");

		bubi::SlowTimer &slow_timer = bubi::SlowTimer::Instance();
		if (!bubi::g_enable_ || !slow_timer.Initialize(1)){
			LOG_ERROR_ERRNO("Initialize slow timer failed", STD_ERR_CODE, STD_ERR_DESC);
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::SlowTimer::Exit, &slow_timer));
		LOG_INFO("Initialize slow timer with " FMT_SIZE " successful", utils::System::GetCpuCoreCount());

		bubi::WebSocketServer &ws_server = bubi::WebSocketServer::Instance();
		if (!bubi::g_enable_ || !ws_server.Initialize(bubi::Configure::Instance().wsserver_configure_)) {
			LOG_ERROR("Initialize web server failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::WebSocketServer::Exit, &ws_server));
		LOG_INFO("Initialize web server successful");

		bubi::WebServer &web_server = bubi::WebServer::Instance();
		if (!bubi::g_enable_ || !web_server.Initialize(bubi::Configure::Instance().webserver_configure_)) {
			LOG_ERROR("Initialize web server failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::WebServer::Exit, &web_server));
		LOG_INFO("Initialize web server successful");

		bubi::ContractManager::Initialize(argc, argv);
		//bubi::ContractManager &contract_manager = bubi::LedgerManager::Instance().contract_manager_;
		//if (!contract_manager.Initialize(argc, argv)){
		//	LOG_ERROR("Initialize contract manager failed");
		//	break;
		//}
		//bubiAtExit.Push(std::bind(&bubi::ContractManager::Exit, &contract_manager));
		//LOG_INFO("Initialize contract manager successful");

		RunLoop();

		LOG_INFO("Process begin quit...");
		delete bubi::StatusModule::modules_status_;

	} while (false);

	//bubi::ContractManager::ExitInstance();
	bubi::SlowTimer::ExitInstance();
	bubi::GlueManager::ExitInstance();
	bubi::LedgerManager::ExitInstance();
	bubi::PeerManager::ExitInstance();
	bubi::WebSocketServer::ExitInstance();
	bubi::WebServer::ExitInstance();
	cfca::CFCA::ExitInstance();
	bubi::Configure::ExitInstance();
	bubi::Global::ExitInstance();
	bubi::Storage::ExitInstance();
	utils::Logger::ExitInstance();
	utils::Daemon::ExitInstance();
	
	printf("process exit\n");
}

void RunLoop(){
	int64_t check_module_interval = utils::MICRO_UNITS_PER_SEC;
	int64_t last_check_module = 0;
	while (bubi::g_enable_){
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