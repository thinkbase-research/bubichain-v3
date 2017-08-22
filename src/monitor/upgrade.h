#pragma once
#include <string>
#include <json/json.h>
#include <utils/thread.h>


namespace bubi {
	class ProcessMessage;
	class Upgrade : public utils::Runnable {
	public:
		Upgrade(ProcessMessage* process_message);
		~Upgrade();

		bool Initialize();
		bool Exit();
		void SetItems(const Json::Value value);
		void Run(utils::Thread *thread);
	private:
		bool DownloadFile(const std::string& url_address, const std::string& file_path);
		static size_t DownloadCallback(void* pBuffer, size_t nSize, size_t nMemByte, void* pParam);
	private:
		ProcessMessage* pprocess_message_;
		utils::Thread* thread_ptr_;
		Json::Value value_;
	};
}