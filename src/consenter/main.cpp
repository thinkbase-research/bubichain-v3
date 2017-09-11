#include <utils/headers.h>
#include <common/general.h>
#include <common/configure.h>
#include <common/storage.h>
#include <common/private_key.h>
#include <common/daemon.h>
#include <common/argument.h>
#include <overlay/peer_manager.h>
#include <consensus/consensus_manager.h>
#include "web_server.h"
#include "consenter_manager.h"

void RunLoop();
int main(int argc, char *argv[]){
	utils::Thread::SetCurrentThreadName("bubi-thread");

	utils::Daemon::InitInstance();
	utils::net::Initialize();
	utils::Timer::InitInstance();
	bubi::Configure::InitInstance();
	bubi::Storage::InitInstance();
	bubi::Global::InitInstance();
	bubi::SlowTimer::InitInstance();
	utils::Logger::InitInstance();
	bubi::PeerManager::InitInstance();
	bubi::ConsensusManager::InitInstance();
	bubi::ConsenterManager::InitInstance();
	bubi::WebServer::InitInstance();

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
		std::string config_path = "config/consenter.json";
		if (!utils::File::IsAbsolute(config_path)){
			config_path = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), config_path.c_str());
		}

		if (!config.Load(config_path)){
			LOG_STD_ERRNO("Load configure failed, path(%s)", config_path.c_str(), STD_ERR_CODE, STD_ERR_DESC);
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

		bubi::Storage &storage = bubi::Storage::Instance();
		LOG_INFO("%s,%s => %s", config.db_configure_.keyvalue_db_path_.c_str(), config.db_configure_.rational_db_type_.c_str(), config.db_configure_.rational_string_.c_str());

		if (!bubi::g_enable_ || !storage.Initialize(config.db_configure_.keyvalue_db_path_, config.db_configure_.rational_string_, arg.drop_db_)) {
			LOG_ERROR("Initialize db failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::Storage::Exit, &storage));
		LOG_INFO("Initialize db successful");

		if ( arg.clear_consensus_status_ ){
			bubi::Pbft::ClearStatus();
			LOG_INFO("Clear consensus status successfully");
			break;
		}
		
		if (arg.CompleteDbTask(bubi::Storage::Instance().rational_db(), bubi::Storage::Instance().keyvalue_db(), bubi::Configure::Instance())){
			return 1;
		}

		bubi::Global &global = bubi::Global::Instance();
		if (!bubi::g_enable_ || !global.Initialize()){
			LOG_ERROR_ERRNO("Initialize global variable failed", STD_ERR_CODE, STD_ERR_DESC);
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::Global::Exit, &global));
		LOG_INFO("Initialize global variable successful");

		bubi::ConsensusManager &consensus_manager = bubi::ConsensusManager::Instance();
		if (!bubi::g_enable_ || !consensus_manager.Initialize(bubi::Configure::Instance().validation_configure_)) {
			LOG_ERROR("Initialize consensus manager failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::ConsensusManager::Exit, &consensus_manager));
		LOG_INFO("Initialize consensus manager successful");

		bubi::ConsenterManager &consenster_manager = bubi::ConsenterManager::Instance();
		if (!bubi::g_enable_ || !consenster_manager.Initialize()) {
			LOG_ERROR("Initialize consenter manager failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::ConsenterManager::Exit, &consenster_manager));
		LOG_INFO("Initialize consenter manager successful");

		bubi::PeerManager &p2p = bubi::PeerManager::Instance();
		if (!bubi::g_enable_ || !p2p.Initialize()) {
			LOG_ERROR("Initialize peer network failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::PeerManager::Exit, &p2p));
		LOG_INFO("Initialize peer network successful");

		bubi::SlowTimer &slow_timer = bubi::SlowTimer::Instance();
		if (!bubi::g_enable_ || !slow_timer.Initialize(1)){
			LOG_ERROR_ERRNO("Initialize slow timer failed", STD_ERR_CODE, STD_ERR_DESC);
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::SlowTimer::Exit, &slow_timer));
		LOG_INFO("Initialize slow timer with " FMT_SIZE " successful", utils::System::GetCpuCoreCount());

		bubi::WebServer &web_server = bubi::WebServer::Instance();
		if (!bubi::g_enable_ || !web_server.Initialize(bubi::Configure::Instance().webserver_configure_)) {
			LOG_ERROR("Initialize web server failed");
			break;
		}
		bubiAtExit.Push(std::bind(&bubi::WebServer::Exit, &web_server));
		LOG_INFO("Initialize web server successful");

		RunLoop();

		LOG_INFO("Process begin quit...");
		delete bubi::StatusModule::modules_status_;

	} while (false);

	bubi::SlowTimer::ExitInstance();
	bubi::PeerManager::ExitInstance();
	bubi::WebServer::ExitInstance();
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