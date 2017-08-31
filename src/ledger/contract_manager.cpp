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

#include <utils/logger.h>
#include <common/pb2json.h>
#include "contract_manager.h"
#include "ledger_frm.h"
#include "ledger_manager.h"


namespace bubi{

	std::map<std::string, std::string> ContractManager::jslib_sources;
	const std::string ContractManager::sender_name_ = "sender";
	const std::string ContractManager::this_address_ = "thisAddress";
	const char* ContractManager::main_name_ = "main";
	const std::string ContractManager::trigger_tx_name_ = "trigger";
	const std::string ContractManager::trigger_tx_index_name_ = "triggerIndex";
	const std::string ContractManager::this_header_name_ = "consensusValue";

	v8::Platform* ContractManager::platform_ = nullptr;
	v8::Isolate::CreateParams ContractManager::create_params_;
	ContractManager* ContractManager::executing_contract_ = nullptr;


	ContractManager::ContractManager(){
		LoadJsLibSource();
		tx_do_count_ = 0;
		isolate_ = v8::Isolate::New(create_params_);
		v8::Isolate::Scope isolate_scope(isolate_);
		v8::HandleScope handle_scope(isolate_);

		// Store the request pointer in the JavaScript wrapper.

		if (global_.IsEmpty()) {
			v8::Local<v8::ObjectTemplate>  global = v8::ObjectTemplate::New(isolate_);


			global->Set(
				v8::String::NewFromUtf8(isolate_, "callBackLog", v8::NewStringType::kNormal)
				.ToLocalChecked(),
				v8::FunctionTemplate::New(isolate_, ContractManager::CallBackLog, v8::External::New(isolate_, this)));


			global->Set(
				v8::String::NewFromUtf8(isolate_, "callBackGetAccountInfo", v8::NewStringType::kNormal)
				.ToLocalChecked(),
				v8::FunctionTemplate::New(isolate_, ContractManager::CallBackGetAccountInfo, v8::External::New(isolate_, this)));


			global->Set(
				v8::String::NewFromUtf8(isolate_, "callBackGetAccountAsset", v8::NewStringType::kNormal)
				.ToLocalChecked(),
				v8::FunctionTemplate::New(isolate_, ContractManager::CallBackGetAccountAsset, v8::External::New(isolate_, this)));


			global->Set(
				v8::String::NewFromUtf8(isolate_, "callBackGetAccountMetaData", v8::NewStringType::kNormal)
				.ToLocalChecked(),
				v8::FunctionTemplate::New(isolate_, ContractManager::CallBackGetAccountMetaData, v8::External::New(isolate_, this)));


			global->Set(
				v8::String::NewFromUtf8(isolate_, "callBackSetAccountMetaData", v8::NewStringType::kNormal)
				.ToLocalChecked(),
				v8::FunctionTemplate::New(isolate_, ContractManager::CallBackSetAccountMetaData, v8::External::New(isolate_, this)));

			global->Set(
				v8::String::NewFromUtf8(isolate_, "callBackGetLedgerInfo", v8::NewStringType::kNormal)
				.ToLocalChecked(),
				v8::FunctionTemplate::New(isolate_, ContractManager::CallBackGetLedgerInfo, v8::External::New(isolate_, this)));


			global->Set(
				v8::String::NewFromUtf8(isolate_, "callBackGetTransactionInfo", v8::NewStringType::kNormal)
				.ToLocalChecked(),
				v8::FunctionTemplate::New(isolate_, ContractManager::CallBackGetTransactionInfo, v8::External::New(isolate_, this)));


			global->Set(
				v8::String::NewFromUtf8(isolate_, "callBackDoOperation", v8::NewStringType::kNormal)
				.ToLocalChecked(),
				v8::FunctionTemplate::New(isolate_, ContractManager::CallBackDoOperation, v8::External::New(isolate_, this)));

			global->Set(
				v8::String::NewFromUtf8(isolate_, "include", v8::NewStringType::kNormal)
				.ToLocalChecked(),
				v8::FunctionTemplate::New(isolate_, ContractManager::Include, v8::External::New(isolate_, this)));

			global_.Reset(isolate_, global);
		}
	}

	ContractManager::~ContractManager(){

	}



	void ContractManager::Initialize(int argc, char** argv){
		platform_ = v8::platform::CreateDefaultPlatform();
		v8::V8::InitializeExternalStartupData(argv[0]);
		v8::V8::InitializePlatform(platform_);
		if (!v8::V8::Initialize()){
			BUBI_EXIT("v8 Initialize fail");
		}
		create_params_.array_buffer_allocator =
			v8::ArrayBuffer::Allocator::NewDefaultAllocator();
	}

	std::string ContractManager::ReportException(v8::Isolate* isolate, v8::TryCatch* try_catch) {
		v8::HandleScope handle_scope(isolate);
		v8::String::Utf8Value exception(try_catch->Exception());
		const char* exception_string = ToCString(exception);
		v8::Local<v8::Message> message = try_catch->Message();
		std::string error_msg;
		if (message.IsEmpty()) {
			// V8 didn't provide any extra information about this error; just
			// print the exception.
			error_msg = utils::String::AppendFormat(error_msg, "%s", exception_string);
		}
		else {
			// Print (filename):(line number): (message).
			v8::String::Utf8Value filename(message->GetScriptOrigin().ResourceName());
			v8::Local<v8::Context> context(isolate->GetCurrentContext());
			const char* filename_string = ToCString(filename);
			int linenum = message->GetLineNumber(context).FromJust();
			error_msg = utils::String::AppendFormat(error_msg, "%s:%i: %s", filename_string, linenum, exception_string);
			// Print line of source code.
			v8::String::Utf8Value sourceline(
				message->GetSourceLine(context).ToLocalChecked());
			const char* sourceline_string = ToCString(sourceline);
			error_msg = utils::String::AppendFormat(error_msg, "%s", sourceline_string);
			// Print wavy underline (GetUnderline is deprecated).
			int start = message->GetStartColumn(context).FromJust();
			for (int i = 0; i < start; i++) {
				error_msg = utils::String::AppendFormat(error_msg, " ");
			}
			int end = message->GetEndColumn(context).FromJust();
			for (int i = start; i < end; i++) {
				error_msg = utils::String::AppendFormat(error_msg, "^");
			}

			v8::Local<v8::Value> stack_trace_string;
			if (try_catch->StackTrace(context).ToLocal(&stack_trace_string) &&
				stack_trace_string->IsString() &&
				v8::Local<v8::String>::Cast(stack_trace_string)->Length() > 0) {
				v8::String::Utf8Value stack_trace(stack_trace_string);
				const char* stack_trace_string = ToCString(stack_trace);
				error_msg = utils::String::AppendFormat(error_msg, "%s", stack_trace_string);
			}
		}
		//LOG_ERROR("V8ErrorTrace:%s", error_msg.c_str());
		return error_msg;
	}

	bool ContractManager::SourceCodeCheck(const std::string& code, std::string& err_msg){

		v8::Isolate::Scope isolate_scope(isolate_);

		v8::HandleScope handle_scope(isolate_);
		v8::TryCatch try_catch(isolate_);

		v8::Local<v8::ObjectTemplate> templ =
			v8::Local<v8::ObjectTemplate>::New(isolate_, global_);

		v8::Handle<v8::Context> context = v8::Context::New(isolate_, NULL, templ);
		v8::Context::Scope context_scope(context);

		
		auto string_sender = v8::String::NewFromUtf8(isolate_, "", v8::NewStringType::kNormal).ToLocalChecked();
		context->Global()->Set(context, v8::String::NewFromUtf8(isolate_, sender_name_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(), string_sender);


		auto string_contractor = v8::String::NewFromUtf8(isolate_, "", v8::NewStringType::kNormal).ToLocalChecked();
		context->Global()->Set(context, v8::String::NewFromUtf8(isolate_, this_address_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(), string_contractor);

		auto str_json_v8 = v8::String::NewFromUtf8(isolate_, "{}", v8::NewStringType::kNormal).ToLocalChecked();
		auto tx_v8 = v8::JSON::Parse(str_json_v8);
		context->Global()->Set(context,
			v8::String::NewFromUtf8(isolate_, trigger_tx_name_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
			tx_v8);

		v8::Local<v8::Integer> index_v8 = v8::Int32::New(isolate_, 0);
		context->Global()->Set(context,
			v8::String::NewFromUtf8(isolate_, trigger_tx_index_name_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
			index_v8);

		auto v8_consensus_value = v8::String::NewFromUtf8(isolate_, "{}", v8::NewStringType::kNormal).ToLocalChecked();
		auto v8HeadJson = v8::JSON::Parse(v8_consensus_value);
		context->Global()->Set(context,
			v8::String::NewFromUtf8(isolate_, this_header_name_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
			v8HeadJson);

		v8::Local<v8::String> v8src = v8::String::NewFromUtf8(isolate_, code.c_str());
		v8::Local<v8::Script> compiled_script;

		if (!v8::Script::Compile(context, v8src).ToLocal(&compiled_script)){
			err_msg = ReportException(isolate_, &try_catch);
			LOG_ERROR("%s", err_msg.c_str());
			return false;
		}

		/*
		auto result = compiled_script->Run(context).ToLocalChecked();

		v8::Local<v8::String> process_name =
		v8::String::NewFromUtf8(isolate_, main_name_
		, v8::NewStringType::kNormal, strlen(main_name_))
		.ToLocalChecked();


		v8::Local<v8::Value> process_val;

		if (!context->Global()->Get(context, process_name).ToLocal(&process_val) ) {
		err_msg = utils::String::Format("lost of %s function", main_name_);
		LOG_ERROR("%s", err_msg.c_str());
		return false;
		}

		if (!process_val->IsFunction()){
		err_msg = utils::String::Format("lost of %s function", main_name_);
		LOG_ERROR("%s", err_msg.c_str());
		return false;
		}
		*/
		return true;
	}

	bool ContractManager::Execute(const std::string& code, 
		const std::string &input,
		const std::string& token,
		const std::string& sender, 
		const std::string& trigger_tx, 
		int32_t index,
		const std::string& consensus_value,
		std::string& error_msg)
	{
		v8::Isolate::Scope isolate_scope(isolate_);

		v8::HandleScope handle_scope(isolate_);
		v8::TryCatch try_catch(isolate_);

		v8::Local<v8::ObjectTemplate> templ =
			v8::Local<v8::ObjectTemplate>::New(isolate_, global_);

		v8::Handle<v8::Context> context = v8::Context::New(isolate_, NULL, templ);

		v8::Context::Scope context_scope(context);


		v8::Local<v8::Value> vtoken = v8::String::NewFromUtf8(isolate_, token.c_str(), v8::NewStringType::kNormal).ToLocalChecked();
		context->SetSecurityToken(vtoken);

		auto string_sender = v8::String::NewFromUtf8(isolate_, sender.c_str(), v8::NewStringType::kNormal).ToLocalChecked();
		context->Global()->Set(context,
			v8::String::NewFromUtf8(isolate_, sender_name_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
			string_sender);

		auto string_contractor = v8::String::NewFromUtf8(isolate_, token.c_str(), v8::NewStringType::kNormal).ToLocalChecked();
		context->Global()->Set(context,
			v8::String::NewFromUtf8(isolate_, this_address_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
			string_contractor);


		auto str_json_v8 = v8::String::NewFromUtf8(isolate_, trigger_tx.c_str(), v8::NewStringType::kNormal).ToLocalChecked();
		auto tx_v8 = v8::JSON::Parse(str_json_v8);
		context->Global()->Set(context,
			v8::String::NewFromUtf8(isolate_, trigger_tx_name_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
			tx_v8);

		v8::Local<v8::Integer> index_v8 = v8::Int32::New(isolate_, index);
		context->Global()->Set(context,
			v8::String::NewFromUtf8(isolate_, trigger_tx_index_name_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
			index_v8);

		auto v8_consensus_value = v8::String::NewFromUtf8(isolate_, consensus_value.c_str(), v8::NewStringType::kNormal).ToLocalChecked();
		auto v8HeadJson = v8::JSON::Parse(v8_consensus_value);
		context->Global()->Set(context,
			v8::String::NewFromUtf8(isolate_, this_header_name_.c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
			v8HeadJson);

		v8::Local<v8::String> v8src = v8::String::NewFromUtf8(isolate_, code.c_str());
		v8::Local<v8::Script> compiled_script;

		auto back = executing_contract_;
		do
		{
			executing_contract_ = this;
			if (!v8::Script::Compile(context, v8src).ToLocal(&compiled_script)){
				error_msg = ReportException(isolate_, &try_catch);
				break;
			}

			v8::Local<v8::Value> result;
			if (!compiled_script->Run(context).ToLocal(&result)){
				error_msg = ReportException(isolate_, &try_catch);
				break;
			}

			v8::Local<v8::String> process_name =
				v8::String::NewFromUtf8(isolate_, main_name_, v8::NewStringType::kNormal, strlen(main_name_))
				.ToLocalChecked();
			v8::Local<v8::Value> process_val;

			if (!context->Global()->Get(context, process_name).ToLocal(&process_val) ||
				!process_val->IsFunction()) {
				LOG_ERROR("lost of %s function", main_name_);
				break;
			}

			v8::Local<v8::Function> process = v8::Local<v8::Function>::Cast(process_val);

			const int argc = 1;
			v8::Local<v8::String> arg1 = v8::String::NewFromUtf8(isolate_, input.c_str(), v8::NewStringType::kNormal).ToLocalChecked();

			v8::Local<v8::Value> argv[argc];
			argv[0] = arg1;

			v8::Local<v8::Value> callresult;
			if (!process->Call(context, context->Global(), argc, argv).ToLocal(&callresult)){
				error_msg = ReportException(isolate_, &try_catch);
				break;
			}

			executing_contract_ = back;
			return true;
		} while (false);
		executing_contract_ = back;
		return false;
	}



	bool ContractManager::Exit(){
		return true;
	}


	bool ContractManager::LoadJsLibSource() {
		std::string lib_path = utils::String::Format("%s/jslib", utils::File::GetBinHome().c_str());
		utils::FileAttributes files;
		utils::File::GetFileList(lib_path, "*.js", files);
		for (utils::FileAttributes::iterator iter = files.begin(); iter != files.end(); iter++) {
			utils::FileAttribute attr = iter->second;
			utils::File file;
			std::string file_path = utils::String::Format("%s/%s", lib_path.c_str(), iter->first.c_str());
			if (!file.Open(file_path, utils::File::FILE_M_READ)) {
				LOG_ERROR_ERRNO("Open js lib file failed, path(%s)", file_path.c_str(), STD_ERR_CODE, STD_ERR_DESC);
				continue;
			}

			std::string data;
			if (file.ReadData(data, 10 * utils::BYTES_PER_MEGA) < 0) {
				LOG_ERROR_ERRNO("Read js lib file failed, path(%s)", file_path.c_str(), STD_ERR_CODE, STD_ERR_DESC);
				continue;
			}

			jslib_sources[iter->first] = data;
		}

		return true;
	}

	const char* ContractManager::ToCString(const v8::String::Utf8Value& value) {
		return *value ? *value : "<string conversion failed>";
	}

	void ContractManager::Include(const v8::FunctionCallbackInfo<v8::Value>& args) {
		do {
			if (args.Length() != 1) {
				LOG_ERROR("Include parameter error, args length(%d) not equal 1", args.Length());
				args.GetReturnValue().Set(false);
				break;
			}

			if (!args[0]->IsString()) {
				LOG_ERROR("Include parameter error, parameter should be a String");
				args.GetReturnValue().Set(false);
				break;
			}
			v8::String::Utf8Value str(args[0]);

			std::map<std::string, std::string>::iterator find_source = jslib_sources.find(*str);
			if (find_source == jslib_sources.end()) {
				LOG_ERROR("Can't find the include file(%s) in jslib directory", *str);
				args.GetReturnValue().Set(false);
				break;
			}


			v8::TryCatch try_catch(args.GetIsolate());
			std::string js_file = find_source->second; //load_file(*str);

			v8::Local<v8::String> source = v8::String::NewFromUtf8(args.GetIsolate(), js_file.c_str());
			v8::Local<v8::Script> script;
			if (!v8::Script::Compile(args.GetIsolate()->GetCurrentContext(), source).ToLocal(&script)) {
				ReportException(args.GetIsolate(), &try_catch);
				break;
			}

			v8::Local<v8::Value> result;
			if (!script->Run(args.GetIsolate()->GetCurrentContext()).ToLocal(&result)) {
				ReportException(args.GetIsolate(), &try_catch);
			}
		} while (false);
		//return v8::Undefined(args.GetIsolate());
	}


	void ContractManager::CallBackGetAccountAsset(const v8::FunctionCallbackInfo<v8::Value>& args) {
		if (args.Length() != 2) {
			LOG_ERROR("parameter error");
			args.GetReturnValue().Set(false);
			return;
		}

		do{
			v8::HandleScope handle_scope(args.GetIsolate());
			if (!args[0]->IsString()){
				LOG_ERROR("contract execute error,CallBackGetAccountAsset, parameter 1 should be a String");
				break;
			}
			auto address = std::string(ToCString(v8::String::Utf8Value(args[0])));

			if (!args[1]->IsObject()){
				LOG_ERROR("contract execute error,CallBackGetAccountAsset parameter 2 should be a object");
				break;
			}
			auto ss = v8::JSON::Stringify(args.GetIsolate()->GetCurrentContext(), args[1]->ToObject()).ToLocalChecked();
			auto strjson = std::string(ToCString(v8::String::Utf8Value(ss)));
			Json::Value json;
			json.fromString(strjson);

			protocol::AssetProperty property;
			if (!Json2Proto(json, property)){
				LOG_ERROR("contract execute error,CallBackGetAccountAsset,parameter property not valid");
				break;
			}


			bubi::AccountFrm::pointer account_frm = nullptr;
			auto environment = LedgerManager::Instance().transaction_stack_.top()->environment_;
			if (!environment->GetEntry(address, account_frm)){
				break;
			}

			protocol::Asset asset;
			if (!account_frm->GetAsset(property, asset)){
				break;
			}

			Json::Value json_asset = bubi::Proto2Json(asset);
			std::string strvalue = json_asset.toFastString();

			v8::Local<v8::String> returnvalue = v8::String::NewFromUtf8(
				args.GetIsolate(), strvalue.c_str(), v8::NewStringType::kNormal).ToLocalChecked();
			args.GetReturnValue().Set(v8::JSON::Parse(returnvalue));

		} while (false);
	}



	void ContractManager::CallBackGetAccountMetaData(const v8::FunctionCallbackInfo<v8::Value>& args) {
		do
		{
			if (args.Length() != 2) {
				LOG_ERROR("parameter error");
				args.GetReturnValue().Set(false);
				break;
			}
			v8::HandleScope handle_scope(args.GetIsolate());

			if (!args[0]->IsString()){
				LOG_ERROR("contract execute error,CallBackGetAccountStorage, parameter 0 should be a String");
				break;
			}

			v8::String::Utf8Value str(args[0]);
			std::string address(ToCString(str));

			if (!args[1]->IsString()){
				LOG_ERROR("contract execute error,CallBackGetAccountStorage, parameter 1 should be a String");
				break;
			}
			std::string key = ToCString(v8::String::Utf8Value(args[1]));

			bubi::AccountFrm::pointer account_frm = nullptr;
			auto environment = LedgerManager::Instance().transaction_stack_.top()->environment_;
			if (!environment->GetEntry(address, account_frm)){
				break;
			}

			protocol::KeyPair kp;
			if (!account_frm->GetMetaData(key, kp)){
				break;
			}

			Json::Value json = bubi::Proto2Json(kp);
			std::string strvalue = json.toFastString();

			v8::Local<v8::String> returnvalue = v8::String::NewFromUtf8(
				args.GetIsolate(), strvalue.c_str(), v8::NewStringType::kNormal).ToLocalChecked();
			args.GetReturnValue().Set(v8::JSON::Parse(returnvalue));
			return;
		} while (false);
		args.GetReturnValue().Set(false);
	}


	void ContractManager::CallBackSetAccountMetaData(const v8::FunctionCallbackInfo<v8::Value>& args){
		do
		{
			if (args.Length() != 1) {
				LOG_ERROR("parameter error");
				args.GetReturnValue().Set(false);
				break;
			}
			v8::HandleScope handle_scope(args.GetIsolate());

			v8::String::Utf8Value token(args.GetIsolate()->GetCurrentContext()->GetSecurityToken()->ToString());
			std::string contractor(ToCString(token));

			if (!args[0]->IsObject()){
				LOG_ERROR("contract execute error,CallBackSetAccountStorage, parameter 0 should be a object");
				break;
			}
			v8::Local<v8::String> str = v8::JSON::Stringify(args.GetIsolate()->GetCurrentContext(), args[0]->ToObject()).ToLocalChecked();
			v8::String::Utf8Value  utf8(str);

			protocol::TransactionEnv txenv;
			txenv.mutable_transaction()->set_source_address(contractor);
			protocol::Operation *ope = txenv.mutable_transaction()->add_operations();

			Json::Value json;
			if (!json.fromCString(ToCString(utf8))){
				LOG_ERROR("fromCString fail, fatal error");
				break;
			}

			ope->set_type(protocol::Operation_Type_SET_METADATA);
			protocol::OperationSetMetadata proto_setmetadata;
			Json2Proto(json, proto_setmetadata);
			ope->mutable_set_metadata()->CopyFrom(proto_setmetadata);
			LedgerManager::Instance().DoTransaction(txenv);
			args.GetReturnValue().Set(true);
			return;
		} while (false);
		args.GetReturnValue().Set(false);
	}


	//
	void ContractManager::CallBackGetAccountInfo(const v8::FunctionCallbackInfo<v8::Value>& args) {
		do
		{
			if (args.Length() != 1) {
				LOG_ERROR("parameter error");
				args.GetReturnValue().Set(false);
				break;
			}

			v8::HandleScope handle_scope(args.GetIsolate());
			if (!args[0]->IsString()){
				LOG_ERROR("CallBackGetAccountInfo, parameter 0 should be a String");
				break;
			}

			v8::String::Utf8Value str(args[0]);
			std::string address(ToCString(str));

			bubi::AccountFrm::pointer account_frm = nullptr;

			auto environment = LedgerManager::Instance().transaction_stack_.top()->environment_;
			if (!environment->GetEntry(address, account_frm))
				break;

			Json::Value json = bubi::Proto2Json(account_frm->GetProtoAccount());
			v8::Local<v8::String> returnvalue = v8::String::NewFromUtf8(
				args.GetIsolate(), json.toFastString().c_str(), v8::NewStringType::kNormal).ToLocalChecked();
			args.GetReturnValue().Set(v8::JSON::Parse(returnvalue));

			return;
		} while (false);
		args.GetReturnValue().Set(false);
	}

	void ContractManager::CallBackDoOperation(const v8::FunctionCallbackInfo<v8::Value>& args) {


		do {
			if (args.Length() != 1) {
				args.GetReturnValue().SetNull();
				LOG_ERROR("parameter error");
				break;
			}
			v8::HandleScope handle_scope(args.GetIsolate());

			v8::String::Utf8Value token(args.GetIsolate()->GetCurrentContext()->GetSecurityToken()->ToString());
			std::string contractor(ToCString(token));

			v8::Local<v8::Object> obj = args[0]->ToObject();
			if (obj->IsNull()){
				LOG_ERROR("CallBackDoOperation, parameter 0 should not be null");
				break;
			}

			auto str = v8::JSON::Stringify(args.GetIsolate()->GetCurrentContext(), obj).ToLocalChecked();

			//v8::Local<v8::String> str = v8::JSON::Stringify(args.GetIsolate()->GetCurrentContext()/*context*/, obj).ToLocalChecked();
			v8::String::Utf8Value utf8value(str);
			const char* strdata = ToCString(utf8value);
			Json::Value transaction_json;

			if (!transaction_json.fromCString(strdata)){
				LOG_ERROR("string to json failed, string=%s", strdata);
				break;
			}

			protocol::Transaction transaction;
			if (!Json2Proto(transaction_json, transaction)){
				LOG_ERROR("json to protocol object failed: json=%s", strdata);
				break;
			}

			transaction.set_source_address(contractor);

			for (int i = 0; i < transaction.operations_size(); i++){
				protocol::Operation*  ope = transaction.mutable_operations(i);
				ope->set_source_address(contractor);
			}

			//transaction.set_nonce(contract_account->GetAccountNonce());			
			protocol::TransactionEnv env;
			env.mutable_transaction()->CopyFrom(transaction);

			if (!LedgerManager::Instance().DoTransaction(env)){
				break;
			}

			args.GetReturnValue().Set(true);

			return;
		} while (false);

		args.GetReturnValue().Set(false);

	}

	void ContractManager::CallBackLog(const v8::FunctionCallbackInfo<v8::Value>& args) {
		LOG_INFO("CallBackLog");

		if (args.Length() < 1){
			args.GetReturnValue().Set(false);
			return;
		}
		v8::HandleScope scope(args.GetIsolate());

		v8::String::Utf8Value token(args.GetIsolate()->GetCurrentContext()->GetSecurityToken()->ToString());

		v8::Local<v8::String> str;
		if (args[0]->IsObject()){
			v8::Local<v8::Object> obj = args[0]->ToObject(args.GetIsolate());
			str = v8::JSON::Stringify(args.GetIsolate()->GetCurrentContext(), obj).ToLocalChecked();
		}
		else {
			str = args[0]->ToString();
		}

		auto type = args[0]->TypeOf(args.GetIsolate());
		if (v8::String::NewFromUtf8(args.GetIsolate(), "undefined", v8::NewStringType::kNormal).ToLocalChecked()->Equals(type)){
			LOG_INFO("undefined type");
			return;
		}

		//
		auto context = args.GetIsolate()->GetCurrentContext();
		auto sender = args.GetIsolate()->GetCurrentContext()->Global()->Get(context,
			v8::String::NewFromUtf8(args.GetIsolate(), sender_name_.c_str(), v8::NewStringType::kNormal).ToLocalChecked()).ToLocalChecked();
		v8::String::Utf8Value utf8_sender(sender->ToString());
		//
		v8::String::Utf8Value utf8value(str);
		LOG_INFO("LogCallBack[%s:%s]\n%s", ToCString(token), ToCString(utf8_sender), ToCString(utf8value));
	}

	//
	void ContractManager::CallBackGetTransactionInfo(const v8::FunctionCallbackInfo<v8::Value>& args) {
		if (args.Length() != 1) {
			LOG_ERROR("parameter error");
			args.GetReturnValue().Set(false);
			return;
		}

		v8::HandleScope handle_scope(args.GetIsolate());
		v8::String::Utf8Value str(args[0]);
		std::string hash(ToCString(str));
		bubi::TransactionFrm txfrm;
		std::string hashBin = utils::String::HexStringToBin(hash);
		if (protocol::ERRCODE_SUCCESS == txfrm.LoadFromDb(hashBin)){
			Json::Value json = bubi::Proto2Json(txfrm.GetProtoTxEnv());
			std::string strvalue = json.toStyledString();
			v8::Local<v8::String> returnvalue = v8::String::NewFromUtf8(
				args.GetIsolate(), strvalue.c_str(), v8::NewStringType::kNormal).ToLocalChecked();
			args.GetReturnValue().Set(v8::JSON::Parse(returnvalue));
		}
		else{
			args.GetReturnValue().Set(false);
		}
	}

	//
	void ContractManager::CallBackGetLedgerInfo(const v8::FunctionCallbackInfo<v8::Value>& args) {
		if (args.Length() != 1) {
			LOG_ERROR("parameter error");
			args.GetReturnValue().Set(false);
			return;
		}

		v8::HandleScope handle_scope(args.GetIsolate());
		v8::String::Utf8Value str(args[0]);
		std::string key(ToCString(str));

		int64_t seq = utils::String::Stoi64(key);

		LedgerFrm lfrm;
		if (lfrm.LoadFromDb(seq)){

			std::string strvalue = bubi::Proto2Json(lfrm.GetProtoHeader()).toStyledString();
			v8::Local<v8::String> returnvalue = v8::String::NewFromUtf8(
				args.GetIsolate(), strvalue.c_str(), v8::NewStringType::kNormal).ToLocalChecked();

			args.GetReturnValue().Set(v8::JSON::Parse(returnvalue));
		}
		else{
			args.GetReturnValue().Set(false);
		}
	}

	ContractManager* ContractManager::UnwrapContract(v8::Local<v8::Object> obj){
		v8::Local<v8::External> field = v8::Local<v8::External>::Cast(obj->GetInternalField(0));
		void* ptr = field->Value();
		return static_cast<ContractManager*>(ptr);
	}

	//bool ContractManager::DoTransaction(protocol::TransactionEnv& env){
	//	auto back = LedgerManager::Instance().transaction_stack_.second;
	//	std::shared_ptr<AccountFrm> source_account;
	//	back->environment_->GetEntry(env.transaction().source_address(), source_account);
	//	env.mutable_transaction()->set_nonce(source_account->GetAccountNonce() + 1);
	//	auto txfrm = std::make_shared<bubi::TransactionFrm >(env);
	//	//LedgerManager::Instance().execute_transaction_.second = txfrm;

	//	auto header = std::make_shared<protocol::LedgerHeader>(LedgerManager::Instance().closing_ledger_->GetProtoHeader());

	//	if (txfrm->ValidForParameter()){
	//		txfrm->Apply(header, true);
	//	}

	//	if (txfrm->GetResult().code() == protocol::ERRCODE_SUCCESS){
	//		txfrm->AllCommit();
	//	}

	//	//LedgerManager::Instance().execute_transaction_.second = back;
	//	return txfrm->GetResult().code() == protocol::ERRCODE_SUCCESS;
	//}
}