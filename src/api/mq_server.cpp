#include <utils/headers.h>
#include <common/general.h>
#include <common/configure.h>
#include "mq_server.h"
#include "slave/master_service.h"
#include "slave/slave_service.h"
#include "monitor/monitor_master.h"
#include <overlay/peer_manager.h>
#include <ledger/operation_frm.h>
namespace bubi {

    MQServer::MQServer()
		: PipelineServer(BROADCAST)
    {
        AddHandler(ZMQ_CHAIN_HELLO, MQServer::OnChainHello);
        AddHandler(ZMQ_CHAIN_PEER_MESSAGE, MQServer::OnChainPeerMessage);
		AddHandler(ZMQ_CHAIN_SUBMITTRANSACTION, MQServer::OnSubmitTransaction);

		init_ = false;
    }

    MQServer::~MQServer()
    {

    }

    bool MQServer::Initialize(MqServerConfigure & mq_server_configure)
    {

		if (!PipelineServer::Initialize("api_mqs", mq_server_configure.pipeline_configure_.send_address_, mq_server_configure.pipeline_configure_.recv_address_, mq_server_configure.pipeline_configure_.workers_count_)){
			return false;
		}
		bind();
		init_ = true;
		return true;
    }

    bool MQServer::Exit()
    {
        return PipelineServer::Exit();
    }

	bool MQServer::Send(const ZMQTaskType type, const std::string& buf){
		do
		{
			//安全检查，未初始化的mqserver不能调用
			if (!init_)
				break;

			utils::WriteLockGuard guard(send_list_mutex_);
			if (send_list_.size() > SEND_MAX_SIZE)
				break;

		//	LOG_INFO("mqserver message join the send list");
			send_list_.push_back(std::make_pair(type, buf));
			return true;
		} while (false);
		return false;
	}

	void MQServer::Recv(const ZMQTaskType type, std::string& buf){
		if (!init_)
			return;

		PipelineServer::Recv(type, buf);
	}

	void MQServer::OnTimer(int64_t current_time){
		PipelineServer::OnTimer(current_time);

		utils::WriteLockGuard guardw(send_list_mutex_);
		if (send_list_.size() > 0){
		//	LOG_INFO("send message remove from send list");
			std::pair<ZMQTaskType, std::string> &pa = send_list_.front();
			PipelineServer::Send(pa.first, pa.second);
			send_list_.pop_front();
		}
        		
	}
	void MQServer::OnSlowTimer(int64_t current_time){
		PipelineServer::OnSlowTimer(current_time);
	}
    
    void MQServer::OnChainHello(const char* msg, int len, std::string &reply)
    {
		protocol::ChainStatus cmsg;
		cmsg.set_bubi_version(General::BUBI_VERSION);
		cmsg.set_ledger_version(General::LEDGER_VERSION);
		cmsg.set_self_addr(PeerManager::Instance().GetPeerNodeAddress());
		cmsg.set_timestamp(utils::Timestamp::HighResolution());
		MQServer::Instance().Send(ZMQ_CHAIN_STATUS,cmsg.SerializeAsString());
    }

    void MQServer::OnChainPeerMessage(const char* msg, int len, std::string &reply)
    {
		// send peer
        
        protocol::ChainPeerMessage cpm;
        if (!cpm.ParseFromArray(msg, len)){
            LOG_ERROR("ChainPeerMessage FromString fail");
            return;
        }

        bubi::PeerManager::Instance().BroadcastPayLoad(cpm);
    }

	void MQServer::OnSubmitTransaction(const char* msg, int len, std::string &reply){
		protocol::TransactionEnvWrapper tran_env_wrapper;
		protocol::TransactionEnv &tran_env = *tran_env_wrapper.mutable_transaction_env();
		if (!tran_env.ParseFromArray(msg, len)){

		}

		int64_t active_time = utils::Timestamp::HighResolution();
		Result result;
		result.set_code(protocol::ERRCODE_SUCCESS);
		do{
			//check parameter
			const protocol::Transaction &tx = tran_env.transaction();
			if (!bubi::PublicKey::IsAddressValid(tx.source_address())){
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc("transaction 'source_address' parameter error");
				break;
			}

			if (tx.nonce() <= 0){
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc("'sequence_number' value must be greater than 0");
				break;
			}

			if (tx.metadata().size() > METADATA_MAXSIZE){
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc(utils::String::Format("tx 'metadata' value must be Hex,'metadata' value is in the range of 0 through %d", METADATA_MAXSIZE));
				break;
			}

			if (tx.operations_size() <= 0){
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc("transaction operation not exist!");
				break;
			}

			for (int i = 0; i < tx.operations_size(); i++){
				const protocol::Operation &ope = tx.operations(i);
				if (ope.source_address().size() > 0 &&
					!bubi::PublicKey::IsAddressValid(ope.source_address())){
					result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					result.set_desc("operation 'source_address' parameter error");
					break;
				}

				if (ope.metadata().size() > METADATA_MAXSIZE){
					result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
					result.set_desc(utils::String::Format("operation 'metadata' value is in the range of 0 through %d", METADATA_MAXSIZE));
					break;
				}

                switch (ope.type()){
                    case protocol::Operation_Type_CREATE_ACCOUNT:{
                        CheckCreateAccountOpe(ope, result);
                        break;
                    }
                    case protocol::Operation_Type_ISSUE_ASSET:{
                        CheckIssueAsset(ope, result);
                        break;
                    }
                    case protocol::Operation_Type_PAYMENT:{
                        CheckPayment(ope, result);
                        break;
                    }
                    case protocol::Operation_Type_RECORD:{
                        CheckRecord(ope, result);
                        break;
                    }
                    default:
                        break;
                }(ope.type());

				if (result.code() != protocol::ERRCODE_SUCCESS) break;
			}
			if (result.code() != protocol::ERRCODE_SUCCESS) break;

		} while (false);
		
		//commit  result
		std::string transaction_hash;
		std::string transStr = tran_env.transaction().SerializeAsString();
		transaction_hash = HashWrapper::Crypto(transStr);

		// add node signature
		PrivateKey privateKey(bubi::Configure::Instance().p2p_configure_.node_private_key_);
		if (!privateKey.IsValid()) {
			result.set_code(protocol::ERRCODE_INVALID_PRIKEY);
			result.set_desc("signature failed");
		}
		std::string sign = privateKey.Sign(transStr);
		protocol::Signature *signpro = tran_env.add_signatures();
		signpro->set_sign_data(sign);
		signpro->set_public_key(privateKey.GetBase16PublicKey());
		
        if (result.code() == protocol::ERRCODE_SUCCESS){
            bubi::PeerMessage  msg;
            msg.header_.type = PeerMessage::PEER_MESSAGE_TRANSACTION;

            msg.data_ = &tran_env_wrapper;
            std::string peerMessage = msg.ToString();
            std::string transEvnStr = tran_env.SerializeAsString();

            protocol::SlaveVerifyResponse sv_rsp;
            sv_rsp.set_peer_message(peerMessage);
			sv_rsp.set_peer_message_hash(HashWrapper::Crypto(peerMessage));
            sv_rsp.set_transaction_hash(transaction_hash);
			sv_rsp.set_transaction_env_hash(HashWrapper::Crypto(transEvnStr));

            //check signatures
            for (int i = 0; i < tran_env.signatures_size(); i++)
            {
                const protocol::Signature &signature = tran_env.signatures(i);

                //check public key
                PublicKey pubkey(signature.public_key());
                if (!pubkey.IsValid()){
                    //result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
                    //result.set_desc("'public_key' value not exist or parameter error");
                    LOG_ERROR("Invalid publickey (%s)", signature.public_key().c_str());
                    continue;
                }
                bubi::PublicKey pub(signature.public_key());
                sv_rsp.add_address(pub.GetBase16Address());
            }

			if (sv_rsp.address_size() == 0){
				result.set_code(protocol::ERRCODE_INVALID_PUBKEY);
				result.set_desc("invalid pubkey");
			}
			else{
				std::string slaveTransMsg = sv_rsp.SerializeAsString();
				//Send MasterSlave
				bubi::MasterService::GetInstance()->Recv(ZMQ_NEW_TX, slaveTransMsg);
				if (bubi::Configure::Instance().monitor_configure_.real_time_status_){
					//notice monitor Tx state
					std::shared_ptr<Json::Value> tx_status = std::make_shared<Json::Value>();
					(*tx_status)["type"] = 1;
					(*tx_status)["tx_hash"] = Json::Value(sv_rsp.transaction_hash());
					(*tx_status)["active_time"] = Json::Value(active_time);
					bubi::MonitorMaster::Instance().NoticeMonitor(tx_status->toStyledString());
				}
			}
            msg.data_ = NULL;
        }

		if (bubi::Configure::Instance().mqserver_configure_.tx_status)
		{
			//notice mqserver Tx status
			protocol::ChainTxStatus cts;
			cts.set_tx_hash(utils::encode_b16(transaction_hash));
			cts.set_error_code((protocol::ERRORCODE)result.code());
            cts.set_source_address(tran_env.transaction().source_address());
			cts.set_status(result.code() == protocol::ERRCODE_SUCCESS ? protocol::ChainTxStatus_TxStatus_CONFIRMED : protocol::ChainTxStatus_TxStatus_FAILURE);
			cts.set_error_desc(result.desc());
			cts.set_timestamp(utils::Timestamp::Now().timestamp());
			std::string str = cts.SerializeAsString();
			bubi::MQServer::Instance().Send(ZMQ_CHAIN_TX_STATUS, str);
		}
	}
		
	bool MQServer::CheckCreateAccountOpe(const protocol::Operation &ope, Result &result){
		if (!ope.has_create_account()){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("protocol create_account not exist");
			return false;
		}
		const protocol::OperationCreateAccount &ope_crea = ope.create_account();

		if (!bubi::PublicKey::IsAddressValid(ope_crea.dest_address())){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("'dest_address' parameter error");
			return false;
		}

		return true;
	}

	bool MQServer::CheckPayment(const protocol::Operation &ope, Result &result){
		if (!ope.has_payment()){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("protocol payment not exist");
			return false;
		}

		const protocol::OperationPayment &payment = ope.payment();

		if (!bubi::PublicKey::IsAddressValid(payment.destaddress())){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("'dest_address' parameter error");
			return false;
		}

		const protocol::Asset &asset = payment.asset();
		if (asset.amount() <= 0){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("'asset_amount' value must be greater than 0");
			return false;
		}

		const protocol::AssetProperty &property = asset.property();

		//if (property.type() != protocol::AssetProperty_Type_IOU){
		//	result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
		//	result.set_desc("'asset_type' must be IOU");
		//	return false;
		//}

		if (property.code().size() > ASSET_CODE_MAX_SIZE){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc(utils::String::Format("'asset_code' value is in the range of 1 through %d", ASSET_CODE_MAX_SIZE));
			return false;
		}

		if (property.type() == protocol::AssetProperty_Type_IOU){
			if (!bubi::PublicKey::IsAddressValid(property.issuer())){
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc("'asset_issuer'  parameter error");
				return false;
			}

			if (property.code().size() == 0){
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc(utils::String::Format("'asset_code' value is in the range of 1 through %d", ASSET_CODE_MAX_SIZE));
				return false;
			}
		}
		return true;
	}

	bool MQServer::CheckIssueAsset(const protocol::Operation &ope, Result &result){
		if (!ope.has_issue_asset()){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("issue operation not exist");
			return false; 
		}

		const protocol::Asset &asset = ope.issue_asset().asset();
		if (asset.amount() <= 0){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("'asset_amount' parameter error,'asset_amount' value must be greater than 0");
			return false;
		}
		const protocol::AssetProperty &property = asset.property();
		if (property.type() != protocol::AssetProperty_Type_IOU){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("'asset_type' must be IOU");
			return false;
		}

		if (property.code().size() > ASSET_CODE_MAX_SIZE ||
			property.code().size() == 0){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc(utils::String::Format("'asset_code' value is in the range of 1 through %d", ASSET_CODE_MAX_SIZE));
			return false;
		}

		if (!bubi::PublicKey::IsAddressValid(property.issuer())){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("'asset_issuer' parameter error");
			return false;
		}

		return true;
	}

	bool MQServer::CheckRecord(const protocol::Operation &ope, Result &result){
		if (!ope.has_record()){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc("protocol record not exist");
			return false;
		}

		const protocol::OperationRecord &record = ope.record();

		if (record.id().size() == 0 ||
			record.id().size() > RECORD_ID_MAX_SIZE){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc(utils::String::Format("'record_id' parameter error,'record_id' value is in the range of 1 through %d", RECORD_ID_MAX_SIZE));
			return false;
		}

		if (record.ext().size() > METADATA_MAXSIZE){
			result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
			result.set_desc(utils::String::Format("'metadata' size is in the range of 0 through %d", METADATA_MAXSIZE));
			return false;
		}

		if (record.address().size() > 0){
			if (!bubi::PublicKey::IsAddressValid(record.address())){
				result.set_code(protocol::ERRCODE_INVALID_PARAMETER);
				result.set_desc("'record_address' parameter error");
				return false;
			}
		}
		return true;
	}
}