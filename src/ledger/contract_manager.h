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

#ifndef CONTRACT_MANAGER_H_
#define CONTRACT_MANAGER_H_
#include <map>
#include <string>

#include <utils/headers.h>
#include <v8.h>
#include <libplatform/libplatform.h>
#include <libplatform/libplatform-export.h>
#include <proto/cpp/chain.pb.h>

namespace bubi{

	class ContractManager 
	{
		v8::Isolate* isolate_;
		v8::Global<v8::Context> g_context_;
		v8::Local<v8::ObjectTemplate> global_;

	    static std::map<std::string, std::string> jslib_sources;
		static const std::string sender_name_ ;
		static const std::string this_address_;
		static const char* main_name_;
		static const std::string trigger_tx_name_;
		static const std::string trigger_tx_index_name_;
		static const std::string this_header_name_;

		static v8::Platform* 	platform_;
		static v8::Isolate::CreateParams create_params_;
		
	public:
		static ContractManager* executing_contract_;
		int tx_do_count_;
	public:
		
		ContractManager();
		~ContractManager();

		static void Initialize(int argc, char** argv);

		bool Execute(const std::string& code, 
			const std::string &input, 
			const std::string& thisAddress, 
			const std::string& sender,
			const std::string& trigger_tx,
			int32_t index,
			const std::string& consensus_value,
			std::string& error_msg);

		bool SourceCodeCheck(const std::string& code, std::string& err_msg);

		bool Exit();
	private:
		bool LoadJsLibSource();

		static std::string ReportException(v8::Isolate* isolate, v8::TryCatch* try_catch);

		static const char* ToCString(const v8::String::Utf8Value& value);

		static void CallBackLog(const v8::FunctionCallbackInfo<v8::Value>& args);

		static void CallBackGetAccountMetaData(const v8::FunctionCallbackInfo<v8::Value>& args);

		static void CallBackSetAccountMetaData(const v8::FunctionCallbackInfo<v8::Value>& args);

		static void CallBackGetAccountAsset(const v8::FunctionCallbackInfo<v8::Value>& args);

		static void Include(const v8::FunctionCallbackInfo<v8::Value>& args);

		//get account info from an account
		static void CallBackGetAccountInfo(const v8::FunctionCallbackInfo<v8::Value>& args);

		//get a ledger info from a ledger
		static void CallBackGetLedgerInfo(const v8::FunctionCallbackInfo<v8::Value>& args);

		//get transaction info from a transaction
		static void CallBackGetTransactionInfo(const v8::FunctionCallbackInfo<v8::Value>& args);

		//static void CallBackGetThisAddress(const v8::FunctionCallbackInfo<v8::Value>& args);

		//make a transaction
		static void CallBackDoOperation(const v8::FunctionCallbackInfo<v8::Value>& args);

		static ContractManager* UnwrapContract(v8::Local<v8::Object> obj);

		//static bool DoTransaction(protocol::TransactionEnv& env);
	};
}
#endif