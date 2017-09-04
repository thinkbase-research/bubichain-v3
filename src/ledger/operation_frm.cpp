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

#include <ledger/ledger_manager.h>
#include "transaction_frm.h"
#include "operation_frm.h"
#include "contract_manager.h"


namespace bubi {
	OperationFrm::OperationFrm(const protocol::Operation &operation, TransactionFrm* tran, int32_t index) :
		operation_(operation), transaction_(tran), index_(index) {}

	OperationFrm::~OperationFrm() {}

	Result OperationFrm::GetResult() const {
		return result_;
	}

	Result OperationFrm::CheckValid(const protocol::Operation& operation, const std::string &source_address) {
		Result result;
		result.set_code(protocol::ERRCODE_SUCCESS);
		auto type = operation.type();
		const protocol::OperationCreateAccount& create_account = operation.create_account();
		const protocol::OperationPayment& payment = operation.payment();
		const protocol::OperationIssueAsset& issue_asset = operation.issue_asset();

		if (!bubi::PublicKey::IsAddressValid(source_address)) {
			result.set_code(protocol::ERRCODE_ASSET_INVALID);
			result.set_desc(utils::String::Format("Dest address should be a valid account address"));
			return result;
		}
		//const auto &issue_property = issue_asset.
		switch (type) {
		case protocol::Operation_Type_CREATE_ACCOUNT:
		{
			if (!bubi::PublicKey::IsAddressValid(create_account.dest_address())) {
				result.set_code(protocol::ERRCODE_INVALID_ADDRESS);
				result.set_desc(utils::String::Format("dest account address(%s) invalid", create_account.dest_address().c_str()));
				break;
			}

			if (!create_account.has_priv()) {
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc(utils::String::Format("dest account address(%s) has no priv object", create_account.dest_address().c_str()));
				break;
			} 

			const protocol::AccountPrivilege &priv = create_account.priv();
			if (priv.master_weight() < 0 || priv.master_weight() > UINT32_MAX) {
				result.set_code(protocol::ERRCODE_WEIGHT_NOT_VALID);
				result.set_desc(utils::String::Format("Master weight(" FMT_I64 ") is larger than %u  or less 0", priv.master_weight(), UINT32_MAX));
				break;
			}

			//for signers
			bool shouldBreak = false;
			for (int32_t i = 0; i < priv.signers_size(); i++) {
				const protocol::Signer &signer = priv.signers(i);
				if (signer.weight() < 0 || signer.weight() > UINT32_MAX) {
					result.set_code(protocol::ERRCODE_WEIGHT_NOT_VALID);
					result.set_desc(utils::String::Format("Signer weight(" FMT_I64 ") is larger than %u or less 0", signer.weight(), UINT32_MAX));
					shouldBreak = true;
					break;
				}

				if (signer.address() == source_address) {
					result.set_code(protocol::ERRCODE_INVALID_ADDRESS);
					result.set_desc(utils::String::Format("Signer address(%s) can't be equal the source address", signer.address().c_str()));
					shouldBreak = true;
					break;
				}

				if (!PublicKey::IsAddressValid(signer.address())) {
					result.set_code(protocol::ERRCODE_INVALID_ADDRESS);
					result.set_desc(utils::String::Format("Signer address(%s) is not valid", signer.address().c_str()));
					shouldBreak = true;
					break;
				}
			}
			if (shouldBreak) break;

			//for threshold
			if (!priv.has_thresholds()) {
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc(utils::String::Format("dest account address(%s) has no threshold object", create_account.dest_address().c_str()));
				break;
			}

			const protocol::AccountThreshold &threshold = priv.thresholds();
			if (threshold.tx_threshold() < 0) {
				result.set_code(protocol::ERRCODE_THRESHOLD_NOT_VALID);
				result.set_desc(utils::String::Format("Low threshold(" FMT_I64 ") is less than 0", threshold.tx_threshold()));
				break;
			}

			for (int32_t i = 0; i < threshold.type_thresholds_size(); i++) {
				const protocol::OperationTypeThreshold  &type_thresholds = threshold.type_thresholds(i);
				if (type_thresholds.type() > 100 || type_thresholds.type() <= 0) {
					result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					result.set_desc(utils::String::Format("Operation type(%u) not support", type_thresholds.type()));
					break;
				}

				if (type_thresholds.threshold() < 0) {
					result.set_code(protocol::ERRCODE_THRESHOLD_NOT_VALID);
					result.set_desc(utils::String::Format("Operation type(%d) threshold(" FMT_I64 ") is less than 0", (int32_t)type_thresholds.type(), type_thresholds.threshold()));
					break;
				}
			}

			///////////////////////////////////////////////////
			if (create_account.contract().payload() != ""){
				std::string err_msg;
				std::string src = create_account.contract().payload();
				ContractManager a;
				if (!a.SourceCodeCheck(src, err_msg)){
					result.set_code(protocol::ERRCODE_CONTRACT_SYNTAX_ERROR);
					result.set_desc(err_msg);
				}
			}
			break;
		}
		case protocol::Operation_Type_PAYMENT:
		{
			if (payment.has_asset()){
				if (payment.asset().amount() <= 0) {
					result.set_code(protocol::ERRCODE_ASSET_INVALID);
					result.set_desc(utils::String::Format("amount should be bigger than 0"));
					break;
				}

				std::string trim_code = payment.asset().property().code();
				//utils::String::Trim(trim_code);
				if (trim_code.size() == 0 || trim_code.size() > General::ASSET_CODE_MAX_SIZE) {
					result.set_code(protocol::ERRCODE_ASSET_INVALID);
					result.set_desc(utils::String::Format("asset code length should between (0,64]"));
					break;
				}

				if (!bubi::PublicKey::IsAddressValid(payment.asset().property().issuer())) {
					result.set_code(protocol::ERRCODE_ASSET_INVALID);
					result.set_desc(utils::String::Format("asset issuer should be a valid account address"));
					break;
				}
			}

			if (source_address == payment.dest_address()) {
				result.set_code(protocol::ERRCODE_ACCOUNT_SOURCEDEST_EQUAL);
				result.set_desc(utils::String::Format("Source address(%s) equal with dest address", source_address.c_str()));
				break;
			} 

			if (!bubi::PublicKey::IsAddressValid(payment.dest_address())) {
				result.set_code(protocol::ERRCODE_ASSET_INVALID);
				result.set_desc(utils::String::Format("dest address should be a valid account address"));
				break;
			}
			break;
		}

		case protocol::Operation_Type_ISSUE_ASSET:
		{
			if (issue_asset.amount() <= 0) {
				result.set_code(protocol::ERRCODE_ASSET_INVALID);
				result.set_desc(utils::String::Format("amount should be bigger than 0"));
				break;
			}

			std::string trim_code = issue_asset.code();
			trim_code = utils::String::Trim(trim_code);
			if (trim_code.size() == 0 || trim_code.size() > General::ASSET_CODE_MAX_SIZE) {
				result.set_code(protocol::ERRCODE_ASSET_INVALID);
				result.set_desc(utils::String::Format("asset code length should between (0,64]"));
				break;
			}

			break;
		}
		case protocol::Operation_Type_SET_METADATA:
		{
			const protocol::OperationSetMetadata &set_metadata = operation.set_metadata();

			std::string trim = set_metadata.key();
			if (trim.size() == 0 || trim.size() > General::METADATA_KEY_MAXSIZE) {
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc(utils::String::Format("metadata key length should between (0,%d]", General::METADATA_KEY_MAXSIZE));
				break;
			}
			if (set_metadata.value().size() > General::METADATA_MAXSIZE) {
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc(utils::String::Format("metadata data length should between (0,%d]", General::METADATA_MAXSIZE));
				break;
			}
			break;
		}
		case protocol::Operation_Type_SET_SIGNER_WEIGHT:
		{
			const protocol::OperationSetSignerWeight &operation_setoptions = operation.set_signer_weight();
			if (operation_setoptions.master_weight() < -1 || operation_setoptions.master_weight() > UINT32_MAX) {
				result.set_code(protocol::ERRCODE_WEIGHT_NOT_VALID);
				result.set_desc(utils::String::Format("Master weight(" FMT_I64 ") is larger than %u  or less -1", operation_setoptions.master_weight(), UINT32_MAX));
				break;
			}

			for (int32_t i = 0; i < operation_setoptions.signers_size(); i++) {
				const protocol::Signer &signer = operation_setoptions.signers(i);
				if (signer.weight() < 0 || signer.weight() > UINT32_MAX) {
					result.set_code(protocol::ERRCODE_WEIGHT_NOT_VALID);
					result.set_desc(utils::String::Format("Signer weight(" FMT_I64 ") is larger than %u or less 0", signer.weight(), UINT32_MAX));
					break;
				}

				if (signer.address() == source_address) {
					result.set_code(protocol::ERRCODE_INVALID_ADDRESS);
					result.set_desc(utils::String::Format("Signer address(%s) can't be equal the source address", signer.address().c_str()));
					break;
				}

				if (!PublicKey::IsAddressValid(signer.address())) {
					result.set_code(protocol::ERRCODE_INVALID_ADDRESS);
					result.set_desc(utils::String::Format("Signer address(%s) is not valid", signer.address().c_str()));
					break;
				}
			}

			break;
		}
		case protocol::Operation_Type_SET_THRESHOLD:
		{
			const protocol::OperationSetThreshold operation_setoptions = operation.set_threshold();

			if ( operation_setoptions.tx_threshold() < -1) {
				result.set_code(protocol::ERRCODE_THRESHOLD_NOT_VALID);
				result.set_desc(utils::String::Format("Low threshold(" FMT_I64 ") is less than -1", operation_setoptions.tx_threshold()));
				break;
			}

			for (int32_t i = 0; i < operation_setoptions.type_thresholds_size(); i++) {
				const protocol::OperationTypeThreshold  &type_thresholds = operation_setoptions.type_thresholds(i);
				if (type_thresholds.type() > 100 || type_thresholds.type() <= 0) {
					result.set_code(protocol::ERRCODE_THRESHOLD_NOT_VALID);
					result.set_desc(utils::String::Format("Operation type(%u) not support", type_thresholds.type()));
					break;
				}

				if (type_thresholds.threshold()  < 0 ) {
					result.set_code(protocol::ERRCODE_THRESHOLD_NOT_VALID);
					result.set_desc(utils::String::Format("Operation type(%d) threshold(" FMT_I64 ") is less than 0", (int32_t)type_thresholds.type(), type_thresholds.threshold()));
					break;
				}
			}
			break;
		}
		case protocol::Operation_Type_PAY_COIN:
		{
			const protocol::OperationPayCoin &pay_coin = operation.pay_coin();
			if (pay_coin.amount() < 0){
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc(utils::String::Format("Amount should be bigger than 0"));
			}

			if (source_address == payment.dest_address()) {
				result.set_code(protocol::ERRCODE_ACCOUNT_SOURCEDEST_EQUAL);
				result.set_desc(utils::String::Format("Source address(%s) equal with dest address", source_address.c_str()));
				break;
			}

			if (!bubi::PublicKey::IsAddressValid(payment.dest_address())) {
				result.set_code(protocol::ERRCODE_ASSET_INVALID);
				result.set_desc(utils::String::Format("Dest address should be a valid account address"));
				break;
			}
			break;
		}

		case protocol::Operation_Type_Operation_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
			break;
		case protocol::Operation_Type_Operation_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
			break;
		default:{
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc(utils::String::Format("Operation type(%d) invalid", type));
			break;
		}
		}

		return result;
	}

	bool OperationFrm::CheckSignature(std::shared_ptr<Environment> txenvironment) {
		std::string source_address_ = operation_.source_address();
		if (source_address_.size() == 0) {
			source_address_ = transaction_->GetSourceAddress();
		}

		if (!txenvironment->GetEntry(source_address_, source_account_)) {
			result_.set_code(protocol::ERRCODE_ACCOUNT_NOT_EXIST);
			result_.set_desc(utils::String::Format("Source account(%s) not exist", source_address_.c_str()));
			return false;
		}

		utils::StringVector vec;
		vec.push_back(source_address_);
		if (!transaction_->SignerHashPriv(vec, txenvironment, operation_.type())) {
			LOG_ERROR("Check operation's signature failed");
			result_.set_code(protocol::ERRCODE_INVALID_SIGNATURE);
			result_.set_desc(utils::String::Format("Check operation's signature failed"));
			return false;
		}

		return true;
	}


	Result OperationFrm::Apply(std::shared_ptr<Environment>  environment) {
		std::string source_address = operation_.source_address();
		if (source_address.size() == 0) {
			source_address = transaction_->GetSourceAddress();
		}
		if (!environment->GetEntry(source_address, source_account_)) {
			result_.set_code(protocol::ERRCODE_ACCOUNT_NOT_EXIST);
			result_.set_desc(utils::String::Format("Source address(%s) not exist", source_address.c_str()));
			return result_;
		}
		auto type = operation_.type();
		switch (type) {
		case protocol::Operation_Type_UNKNOWN:
			break;
		case protocol::Operation_Type_CREATE_ACCOUNT:
			CreateAccount(environment);
			break;
		case protocol::Operation_Type_PAYMENT:
			Payment(environment);
			break;
		case protocol::Operation_Type_ISSUE_ASSET:
			IssueAsset(environment);
			break;
		case protocol::Operation_Type_SET_METADATA:
			SetMetaData(environment);
			break;
		case protocol::Operation_Type_SET_SIGNER_WEIGHT:
			SetSignerWeight(environment);
			break;
		case protocol::Operation_Type_SET_THRESHOLD:
			SetThreshold(environment);
			break;
		case protocol::Operation_Type_PAY_COIN:

			break;
		case protocol::Operation_Type_Operation_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
			break;
		case protocol::Operation_Type_Operation_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
			break;
		default:
			result_.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result_.set_desc(utils::String::Format("type(%d) not support", type));
			break;
		}
		return result_;
	}

	void OperationFrm::CreateAccount(std::shared_ptr<Environment> environment) {
		//auto &environment = LedgerManager::Instance().execute_environment_;
		const protocol::OperationCreateAccount& createaccount = operation_.create_account();
		do {
			std::shared_ptr<AccountFrm> dest_account;

			if (environment->GetEntry(createaccount.dest_address(), dest_account)) {
				result_.set_code(protocol::ERRCODE_ACCOUNT_DEST_EXIST);
				result_.set_desc(utils::String::Format("Dest address(%s) already exist", createaccount.dest_address().c_str()));
				break;
			}

			protocol::Account account;
			account.mutable_priv()->CopyFrom(createaccount.priv());
			account.set_address(createaccount.dest_address());
			account.mutable_contract()->CopyFrom(createaccount.contract());
			dest_account = std::make_shared<AccountFrm>(account);

			bool success = true;
			for (int i = 0; i < createaccount.metadatas_size(); i++){
				protocol::KeyPair kp;
				kp.CopyFrom(createaccount.metadatas(i));
				if (kp.version() != 0 && kp.version() != 1){
					success = false;
					break;
				}
				kp.set_version(1);
				dest_account->SetMetaData(kp);
			}
			if (!success){
				result_.set_code(protocol::ERRCODE_INVALID_DATAVERSION);
				result_.set_desc(utils::String::Format(
					"set meatadata while create account(%s) version should be 0 or 1 ",
					dest_account->GetAccountAddress().c_str()));
				
				break;
			}

			environment->AddEntry(dest_account->GetAccountAddress(), dest_account);

		} while (false);
	}

	void OperationFrm::IssueAsset(std::shared_ptr<Environment> environment) {


		const protocol::OperationIssueAsset& ope = operation_.issue_asset();
		do {

			protocol::Asset asset_e ;
			protocol::AssetProperty ap;
			ap.set_issuer(source_account_->GetAccountAddress());
			ap.set_code(ope.code());
			if (!source_account_->GetAsset(ap, asset_e)) {
				protocol::Asset asset;
				asset.mutable_property()->CopyFrom(ap);
				asset.set_amount(ope.amount());
				source_account_->SetAsset(asset);
			}
			else {
				int64_t amount = asset_e.amount() + ope.amount();
				if (amount < asset_e.amount() || amount < ope.amount())
				{
					result_.set_code(protocol::ERRCODE_ACCOUNT_ASSET_AMOUNT_TOO_LARGE);
					result_.set_desc(utils::String::Format("IssueAsset asset(%s:%s) overflow(" FMT_I64 " " FMT_I64 ")", ap.issuer().c_str(), ap.code().c_str(), asset_e.amount(), ope.amount()));
					break;
				}
				asset_e.set_amount(amount);
				source_account_->SetAsset(asset_e);
			}

		} while (false);
	}

	void OperationFrm::Payment(std::shared_ptr<Environment> environment) {
		const protocol::OperationPayment& payment = operation_.payment();
		do {
			std::shared_ptr<AccountFrm> dest_account = nullptr;

			if (!environment->GetEntry(payment.dest_address(), dest_account)) {
				result_.set_code(protocol::ERRCODE_ACCOUNT_NOT_EXIST);
				result_.set_desc(utils::String::Format("Dest account(%s) not exist", payment.dest_address().c_str()));
				break;
			}

			if (payment.has_asset()){
				protocol::Asset asset_e;
				protocol::AssetProperty ap = payment.asset().property();
				if (!source_account_->GetAsset(ap, asset_e)) {
					result_.set_code(protocol::ERRCODE_ACCOUNT_ASSET_LOW_RESERVE);
					result_.set_desc(utils::String::Format("asset(%s:%s) low reserve", ap.issuer().c_str(), ap.code().c_str()));
					break;
				}


				int64_t sender_amount = asset_e.amount() - payment.asset().amount();
				if (sender_amount < 0) {
					result_.set_code(protocol::ERRCODE_ACCOUNT_ASSET_LOW_RESERVE);
					result_.set_desc(utils::String::Format("asset(%s:%s) low reserve", ap.issuer().c_str(), ap.code().c_str()));
					break;
				}
				asset_e.set_amount(sender_amount);
				source_account_->SetAsset(asset_e);

				protocol::Asset dest_asset_ptr;
				if (!dest_account->GetAsset(ap, dest_asset_ptr)) {
					dest_account->SetAsset(payment.asset());
				}
				else {
					int64_t receiver_amount = dest_asset_ptr.amount() + payment.asset().amount();
					if (receiver_amount < dest_asset_ptr.amount() || receiver_amount < payment.asset().amount())
					{
						result_.set_code(protocol::ERRCODE_ACCOUNT_ASSET_AMOUNT_TOO_LARGE);
						result_.set_desc(utils::String::Format("Payment asset(%s:%s) overflow(" FMT_I64 " " FMT_I64 ")", ap.issuer().c_str(), ap.code().c_str(), dest_asset_ptr.amount(), payment.asset().amount()));
						break;
					}
					dest_asset_ptr.set_amount(receiver_amount);
					dest_account->SetAsset(dest_asset_ptr);
				}
			}
			
			std::string javascript = dest_account->GetProtoAccount().contract().payload();
			if (!javascript.empty()){
				ContractManager manager;
	
				std::string trigger_str = Proto2Json(transaction_->GetTransactionEnv()).toStyledString();
				std::string err_msg;
				if (!manager.Execute(javascript,
					payment.input(),
					payment.dest_address(),
					source_account_->GetAccountAddress(),
					trigger_str,
					index_,
					Proto2Json(*(transaction_->ledger_->value_)).toFastString(),
					err_msg
					))
				{
					result_.set_code(protocol::ERRCODE_CONTRACT_EXECUTE_FAIL);
					result_.set_desc(err_msg);
					break;
				}
			}
		} while (false);
	}

	void OperationFrm::SetMetaData(std::shared_ptr<Environment> environment) {

		do {
			auto ope = operation_.set_metadata();
			std::string key = ope.key();
			protocol::KeyPair keypair_e ;
			int64_t version = ope.version();

			if (source_account_->GetMetaData(key, keypair_e)) {

				if (version != 0) {
					if (keypair_e.version() + 1 != version) {
						result_.set_code(protocol::ERRCODE_INVALID_DATAVERSION);
						result_.set_desc(utils::String::Format("Data version(" FMT_I64 ") not valid", version));
						break;
					}
				}

				keypair_e.set_version(keypair_e.version() + 1);
				keypair_e.set_value(ope.value());
				source_account_->SetMetaData(keypair_e);

			}
			else {
				if (version != 1 && version != 0) {
					result_.set_code(protocol::ERRCODE_INVALID_DATAVERSION);
					result_.set_desc(utils::String::Format("Data version(" FMT_I64 ") not valid", version));
					break;
				}
				protocol::KeyPair keypair;
				keypair.set_value(ope.value());
				keypair.set_key(ope.key());
				keypair.set_version(1);
				source_account_->SetMetaData(keypair);
			}
		} while (false);

	}

	void OperationFrm::SetSignerWeight(std::shared_ptr<Environment> environment) {
		const protocol::OperationSetSignerWeight &ope = operation_.set_signer_weight();
		do {


			if (ope.master_weight() >= 0) {
				source_account_->SetProtoMasterWeight(ope.master_weight());
			}

			for (int32_t i = 0; i < ope.signers_size(); i++) {
				source_account_->UpdateSigner(ope.signers(i).address(), ope.signers(i).weight());
			}

		} while (false);
	}

	void OperationFrm::SetThreshold(std::shared_ptr<Environment> environment) {
		const protocol::OperationSetThreshold &ope = operation_.set_threshold();
		std::shared_ptr<AccountFrm> source_account = nullptr;

		do {
			if (ope.tx_threshold() >= 0) {
				source_account_->SetProtoTxThreshold(ope.tx_threshold());
			}

			for (int32_t i = 0; i < ope.type_thresholds_size(); i++) {
				source_account_->UpdateTypeThreshold(ope.type_thresholds(i).type(),
					ope.type_thresholds(i).threshold());
			}
		} while (false);
	}

	void OperationFrm::PayCoin(std::shared_ptr<Environment> environment) {
		auto ope = operation_.pay_coin();
		std::string address = ope.dest_address();
		std::shared_ptr<AccountFrm> dest_account_ptr = nullptr;
		do {
			if (!environment->GetEntry(address, dest_account_ptr)) {
				result_.set_code(protocol::ERRCODE_ACCOUNT_NOT_EXIST);
				result_.set_desc(utils::String::Format("Account(%s) not exist", address.c_str()));
				break;
			}

			protocol::Account& proto_source_account = source_account_->GetProtoAccount();
			protocol::Account& proto_dest_account = dest_account_ptr->GetProtoAccount();

			if (proto_source_account.balance() < ope.amount()){
				result_.set_code(protocol::ERRCODE_ACCOUNT_LOW_RESERVE);
				result_.set_desc(utils::String::Format("Account(%s) ballance(" FMT_I64 ") not enough to pay (" FMT_I64 ")",
					address.c_str(), 
					proto_source_account.balance(),
					ope.amount()
					));
				break;
			}
			int64_t new_balance = proto_source_account.balance() - ope.amount();
			proto_source_account.set_balance(new_balance);
			proto_dest_account.set_balance(proto_dest_account.balance() + ope.amount());
			
			std::string javascript = dest_account_ptr->GetProtoAccount().contract().payload();
			if (!javascript.empty()){
				ContractManager manager;
				std::string trigger_str = Proto2Json(transaction_->GetTransactionEnv()).toStyledString();
				std::string err_msg;
				if (!manager.Execute(javascript,
					ope.input(),
					ope.dest_address(),
					source_account_->GetAccountAddress(),
					trigger_str,
					index_,
					Proto2Json(*(transaction_->ledger_->value_)).toFastString(),
					err_msg))
				{
					result_.set_code(protocol::ERRCODE_CONTRACT_EXECUTE_FAIL);
					result_.set_desc(err_msg);
					break;
				}
			}
		} while (false);
	}
}


