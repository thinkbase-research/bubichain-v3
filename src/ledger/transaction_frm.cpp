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

#include <utils/crypto.h>
#include <common/storage.h>
#include <common/pb2json.h>
#include <main/configure.h>
#include <ledger/ledger_manager.h>
#include "transaction_frm.h"
#include "contract_manager.h"

#include "ledger_frm.h"
namespace bubi {

	TransactionFrm::TransactionFrm() :
		apply_time_(0),
		result_(),
		transaction_env_(),
		hash_(),
		full_hash_(),
		data_(),
		full_data_(),
		valid_signature_(),
		ledger_(),
		incoming_time_(utils::Timestamp::HighResolution())
		{
		utils::AtomicInc(&bubi::General::tx_new_count);
	}


	TransactionFrm::TransactionFrm(const protocol::TransactionEnv &env, std::shared_ptr<Environment> envir) :
		apply_time_(0),
		result_(),
		transaction_env_(env),
		valid_signature_(),
		ledger_(),
		incoming_time_(utils::Timestamp::HighResolution()){
		Initialize();
		utils::AtomicInc(&bubi::General::tx_new_count);
		environment_ = std::make_shared<Environment>(envir.get());
	}

	TransactionFrm::~TransactionFrm() {
		utils::AtomicInc(&bubi::General::tx_delete_count);
	}

	void TransactionFrm::ToJson(Json::Value &result) {
		result = Proto2Json(transaction_env_);
		result["error_code"] = result_.code();
		result["close_time"] = result_.close_time_;
		result["ledger_seq"] = result_.ledger_seq_;
		result["hash"] = utils::String::BinToHexString(hash_);
	}

	void TransactionFrm::Initialize() {
		const protocol::Transaction &tran = transaction_env_.transaction();
		data_ = tran.SerializeAsString();
		hash_ = HashWrapper::Crypto(data_);
		full_data_ = transaction_env_.SerializeAsString();
		full_hash_ = HashWrapper::Crypto(full_data_);

		for (int32_t i = 0; i < transaction_env_.signatures_size(); i++) {
			const protocol::Signature &signature = transaction_env_.signatures(i);
			PublicKey pubkey(signature.public_key());

			if (!pubkey.IsValid()) {
				LOG_ERROR("Invalid publickey(%s)", signature.public_key().c_str());
				continue;
			}
			if (!PublicKey::Verify(data_, signature.sign_data(), signature.public_key())) {
				LOG_ERROR("Invalid signature data(%s)", utils::String::BinToHexString(signature.SerializeAsString()).c_str());
				continue;
			}
			valid_signature_.insert(pubkey.GetBase16Address());
		}
	}

	std::string TransactionFrm::GetContentHash() const {
		return hash_;
	}

	std::string TransactionFrm::GetContentData() const {
		return data_;
	}

	std::string TransactionFrm::GetFullHash() const {
		return full_hash_;
	}

	const protocol::TransactionEnv &TransactionFrm::GetTransactionEnv() const {
		return transaction_env_;
	}

	std::string TransactionFrm::GetSourceAddress() const {
		const protocol::Transaction &tran = transaction_env_.transaction();
		return tran.source_address();
	}

	int64_t TransactionFrm::GetNonce() const {
		return transaction_env_.transaction().nonce();
	}


	bool TransactionFrm::ValidForApply(/*std::shared_ptr<Environment> environment*/) {
		do
		{
			if (!ValidForParameter())
				break;

			std::string str_address = transaction_env_.transaction().source_address();
			AccountFrm::pointer source_account;

			if (!environment_->GetEntry(str_address, source_account)) {
				LOG_ERROR("Source account(%s) does not exists", str_address.c_str());
				result_.set_code(protocol::ERRCODE_ACCOUNT_NOT_EXIST);
				break;
			}

			//判断序号是否正确
			int64_t last_seq = source_account->GetAccountNonce();
			if (last_seq + 1 != GetNonce()) {
				LOG_ERROR("Account(%s) Tx sequence(" FMT_I64 ") doesnot match reserve sequence (" FMT_I64 " + 1)",
					str_address.c_str(),
					GetNonce(),
					last_seq);
				result_.set_code(protocol::ERRCODE_BAD_SEQUENCE);
				break;
			}

			utils::StringVector vec;
			vec.push_back(transaction_env_.transaction().source_address());
			if (!SignerHashPriv(vec, NULL, -1)) {
				result_.set_code(protocol::ERRCODE_INVALID_SIGNATURE);
				result_.set_desc(utils::String::Format("Tx(%s) signatures not enough weight", utils::String::BinToHexString(hash_).c_str()));
				LOG_ERROR(result_.desc().c_str());
				break;
			}
			return true;
		} while (false);

		return false;
	}

	bool TransactionFrm::CheckValid(int64_t last_seq) {
		AccountFrm::pointer source_account;
		if (!Environment::AccountFromDB(GetSourceAddress(), source_account)) {
			result_.set_code(protocol::ERRCODE_ACCOUNT_NOT_EXIST);
			result_.set_desc(utils::String::Format("Source account(%s) not exist", GetSourceAddress().c_str()));
			LOG_ERROR("%s", result_.desc().c_str());
			return false;
		}

		if (GetNonce() <= source_account->GetAccountNonce()) {
			result_.set_code(protocol::ERRCODE_BAD_SEQUENCE);
			result_.set_desc(utils::String::Format("Tx nonce(" FMT_I64 ") too small, the account(%s) nonce is (" FMT_I64 ")",
				GetNonce(), GetSourceAddress().c_str(), source_account->GetAccountNonce()));
			LOG_ERROR("%s", result_.desc().c_str());
			return false;
		}

		if (!ValidForParameter())
			return false;

		if (last_seq == 0 && GetNonce() != source_account->GetAccountNonce() + 1) {
			
			result_.set_code(protocol::ERRCODE_BAD_SEQUENCE);
			result_.set_desc(utils::String::Format("Account(%s) tx sequence(" FMT_I64 ")  doesnot match  reserve sequence (" FMT_I64 " + 1), txhash(%s)",
				GetSourceAddress().c_str(),
				GetNonce(),
				source_account->GetAccountNonce(),
				utils::String::Bin4ToHexString(GetContentHash()).c_str()));
			LOG_ERROR("%s", result_.desc().c_str());
			return false;
		}

		if (last_seq > 0 && (GetNonce() != last_seq + 1)) {
			result_.set_code(protocol::ERRCODE_BAD_SEQUENCE);
			result_.set_desc(utils::String::Format("Account(%s) Tx sequence(" FMT_I64 ")  doesnot match  reserve sequence (" FMT_I64 " + 1)",
				GetSourceAddress().c_str(),
				GetNonce(),
				last_seq));
			LOG_ERROR("%s", result_.desc().c_str());
			return false;
		}
		return true;
	}

	bool TransactionFrm::ValidForParameter() {
		const protocol::Transaction &tran = transaction_env_.transaction();
		const LedgerConfigure &ledger_config = Configure::Instance().ledger_configure_;
		if (transaction_env_.ByteSize() >= General::TRANSACTION_LIMIT_SIZE) {
			LOG_ERROR("Transaction env size(%d) larger than limit(%d)",
				transaction_env_.ByteSize(),
				General::TRANSACTION_LIMIT_SIZE);
			result_.set_code(protocol::ERRCODE_TX_SIZE_TOO_BIG);
			return false;
		}

		bool check_valid = true;
		if (tran.operations_size() == 0) {
			LOG_ERROR("Operation size is zero");
			result_.set_code(protocol::ERRCODE_MISSING_OPERATIONS);
			result_.set_desc("Tx missing operation");
			check_valid = false;
			return check_valid;
		}

		if (tran.metadata().size() > General::METADATA_MAXSIZE) {
			result_.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result_.set_desc("Tx's metadata too long");
			LOG_ERROR("%s", result_.desc().c_str());
			check_valid = false;
			return check_valid;
		}


		check_valid = true;
		//判断operation的参数合法性
		int64_t t8 = utils::Timestamp::HighResolution();
		for (int i = 0; i < tran.operations_size(); i++) {
			protocol::Operation ope = tran.operations(i);
			std::string ope_source = !ope.source_address().empty() ? ope.source_address() : GetSourceAddress();
			if (!PublicKey::IsAddressValid(ope_source)) {
				check_valid = false;
				result_.set_code(protocol::ERRCODE_INVALID_ADDRESS);
				result_.set_desc("Source address not valid");
				LOG_ERROR("Invalid operation source address");
				break;
			}

			if (ope.metadata().size() > 0) {
				if (ope.metadata().size() > General::METADATA_MAXSIZE) {
					check_valid = false;
					result_.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					result_.set_desc("Tx's metadata too long");
					LOG_ERROR("%s", result_.desc().c_str());
					break;
				}
			}

			if (ope.expr_condition().size() > 0) {
				if (ope.expr_condition().size() > General::EXPRCONDITION_MAXSIZE || ope.expr_condition().size() == 0) {
					check_valid = false;
					result_.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					result_.set_desc("Expression condition is too long or zero");
					LOG_ERROR("%s", result_.desc().c_str());
					break;
				}

				ExprCondition expr(ope.expr_condition());
				utils::ExprValue value;
				result_ = expr.Parse(value);

				if (result_.code() != 0) {
					check_valid = false;
					result_.set_code(protocol::ERRCODE_EXPR_CONDITION_SYNTAX_ERROR);
					result_.set_desc("Parse expression failed");
					LOG_ERROR_ERRNO("Parse expression of the transaction(hash:%s) failed", utils::String::Bin4ToHexString(hash_).c_str(),
						result_.code(), result_.desc().c_str());
					break;
				}

				if (value.type_ != utils::ExprValue::UNSURE && !value.IsSuccess()) {
					check_valid = false;
					result_.set_code(protocol::ERRCODE_EXPR_CONDITION_RESULT_FALSE);
					result_.set_desc(utils::String::Format("Expression result is false(%s)", value.Print().c_str()));
					LOG_ERROR_ERRNO("Parse expression of the transaction(hash:%s) failed", utils::String::Bin4ToHexString(hash_).c_str(),
						result_.code(), result_.desc().c_str());
					break;
				}
			}

			result_ = OperationFrm::CheckValid(ope, ope_source);

			if (result_.code() != protocol::ERRCODE_SUCCESS) {
				check_valid = false;
				break;
			}
		}
		return check_valid;
	}

	bool TransactionFrm::ValidForSourceSignature(){
		utils::StringVector vec;
		vec.push_back(transaction_env_.transaction().source_address());
		if (!SignerHashPriv(vec, NULL, -1)) {
			result_.set_code(protocol::ERRCODE_INVALID_SIGNATURE);
			result_.set_desc(utils::String::Format("Tx(%s) signatures not enough weight", utils::String::BinToHexString(hash_).c_str()));
			LOG_ERROR(result_.desc().c_str());
			return false;
		}
		return true;
	}

	bool TransactionFrm::SignerHashPriv(utils::StringVector &addresses, std::shared_ptr<Environment> env, int32_t type) const {

		//find not the signer
		AccountFrm::pointer account = NULL;
		if (env) {
			env->GetEntry(addresses.back(), account);
		}
		else{
			Environment::AccountFromDB(addresses.back(), account);
		}

		if (addresses.size() >= 5 || !account) {
			return valid_signature_.find(addresses.back()) != valid_signature_.end();
		}
		else {
			const protocol::AccountPrivilege &priv = account->GetProtoAccount().priv();
			int64_t threshold = priv.thresholds().tx_threshold();
			int64_t type_threshold = account->GetTypeThreshold((protocol::Operation::Type)type);
			if (type_threshold > 0) {
				threshold = type_threshold;
			}

			if (valid_signature_.find(addresses.back()) != valid_signature_.end()) {
				threshold -= priv.master_weight();
			}

			for (int32_t i = 0; i < priv.signers_size(); i++) {
				const protocol::Signer &signer = priv.signers(i);

				//judge if the address exist the path
				bool exist = false;
				for (size_t i = 0; i < addresses.size(); i++) {
					if (addresses[i] == signer.address()) {
						exist = true;
						break;
					}
				}

				utils::StringVector vec_tmp = addresses;
				vec_tmp.push_back(signer.address());
				if (!exist && SignerHashPriv(vec_tmp, env, type)) {
					threshold -= signer.weight();
				}
				if (threshold <= 0) {
					break;
				}
			}

			return threshold <= 0;
		}
	}

	Result TransactionFrm::GetResult() const {
		return result_;
	}


	uint32_t TransactionFrm::LoadFromDb(const std::string &hash) {
		KeyValueDb *db = Storage::Instance().ledger_db();

		std::string txenv_store;
		int res = db->Get(ComposePrefix(General::TRANSACTION_PREFIX, hash), txenv_store);
		if (res < 0) {
			LOG_ERROR("Get transaction failed, %s", db->error_desc().c_str());
			return protocol::ERRCODE_INTERNAL_ERROR;
		}
		else if (res == 0) {
			LOG_ERROR("Tx(%s) not exist", utils::String::BinToHexString(hash).c_str());
			return protocol::ERRCODE_NOT_EXIST;
		}

		protocol::TransactionEnvStore envstor;
		if (!envstor.ParseFromString(txenv_store)) {
			LOG_ERROR("Decode tx(%s) body failed", utils::String::BinToHexString(hash).c_str());
			return protocol::ERRCODE_INTERNAL_ERROR;
		}

		apply_time_ = envstor.close_time();
		transaction_env_ = envstor.transaction_env();

		result_.ledger_seq_ = envstor.ledger_seq();
		result_.close_time_ = envstor.close_time();
		Initialize();
		result_.set_code(envstor.error_code());
		result_.set_desc(envstor.error_desc());
		return 0;
	}

	bool TransactionFrm::CheckTimeout(int64_t expire_time) {
		if (incoming_time_ < expire_time)
			return true;
		result_.set_code(protocol::ERRCODE_TX_TIMEOUT);
		return false;
	}

	bool TransactionFrm::Apply(LedgerFrm* ledger_frm, bool bool_contract) {
		ledger_ = ledger_frm;
		
		
		if (!environment_->parent_){
			BUBI_EXIT("unexpected error. Transaction without an environment?");
		}
		
		//Environment penv(environment_->parent_);
		AccountFrm::pointer source_account;
		std::string str_address = GetSourceAddress();
		if (!environment_->GetEntry(str_address, source_account)) {
			LOG_ERROR("Source account(%s) does not exists", str_address.c_str());
			result_.set_code(protocol::ERRCODE_ACCOUNT_NOT_EXIST);
			return false;
		}
		source_account->NonceIncrease();
		environment_->Commit();

		bool bSucess = true;
		const protocol::Transaction &tran = transaction_env_.transaction();
		for (processing_operation_ = 0; processing_operation_ < tran.operations_size(); processing_operation_++) {
			const protocol::Operation &ope = tran.operations(processing_operation_);
			std::shared_ptr<OperationFrm> opt = std::make_shared< OperationFrm>(ope, this, processing_operation_);
			if (opt == nullptr) {
				LOG_ERROR("Create operation frame failed");
				result_.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				bSucess = false;
				break;
			}

			if (!bool_contract){
				if (!opt->CheckSignature(environment_)) {
					LOG_ERROR("Check signature operation frame failed, txhash(%s)", utils::String::Bin4ToHexString(GetContentHash()).c_str());
					result_ = opt->GetResult();
					bSucess = false;
					break;
				}
			}


			//check the expression
			if (ope.expr_condition().size() > 0) {
				ExprCondition expr(ope.expr_condition());
				utils::ExprValue value;
				result_ = expr.Eval(value);

				if (result_.code() != 0) {
					bSucess = false;
					result_.set_code(protocol::ERRCODE_EXPR_CONDITION_SYNTAX_ERROR);
					LOG_ERROR_ERRNO("Parse expression of the transaction(hash:%s) failed", utils::String::Bin4ToHexString(hash_).c_str(),
						result_.code(), result_.desc().c_str());
					break;
				}

				if (!value.IsSuccess()) {
					bSucess = false;
					result_.set_code(protocol::ERRCODE_EXPR_CONDITION_RESULT_FALSE);
					result_.set_desc(utils::String::Format("Result is false(%s)", value.Print().c_str()));
					LOG_ERROR_ERRNO("Eval expression of the transaction(hash:%s) failed",
						utils::String::Bin4ToHexString(hash_).c_str(), result_.code(), result_.desc().c_str());
					break;
				}
			}

			//opt->SourceRelationTx();
			Result result = opt->Apply(environment_);

			if (result.code() != 0) {
				result_ = opt->GetResult();
				bSucess = false;
				LOG_ERROR("Transaction(%s) operation(%d) apply failed",
					utils::String::BinToHexString(hash_).c_str(), processing_operation_);
				break;
			}
		}
		return bSucess;
	}
}


