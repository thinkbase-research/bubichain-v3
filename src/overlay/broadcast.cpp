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

#include <json/value.h>
#include <utils/headers.h>
#include <common/general.h>
#include "broadcast.h"

namespace bubi{
	BroadcastRecord::BroadcastRecord(int64_t type, const std::string &data, int64_t peer_id) {
		type_ = type;
		data_ = data;
		peers_.insert(peer_id);
		time_stamp_ = utils::Timestamp::HighResolution();
	}

	BroadcastRecord::~BroadcastRecord(){}

	Broadcast::Broadcast(IBroadcastDriver *driver)
		:driver_(driver){}

	Broadcast::~Broadcast(){}

	bool Broadcast::Add(int64_t type, const std::string &data, int64_t peer_id) {
		std::string hash = HashWrapper::Crypto(data);
		utils::MutexGuard guard(mutex_msg_sending_);
		BroadcastRecordMap::iterator result = records_.find(hash);
		if (result == records_.end()){ // we have never seen this message
			BroadcastRecord::pointer record = std::make_shared<BroadcastRecord>(type, data, peer_id);
			records_[hash] = record;
			records_couple_[record->time_stamp_] = hash;
			return true;
		}
		else {
			result->second->peers_.insert(peer_id);
			return false;
		}

		return true;
	}

	void Broadcast::Send(int64_t type, const std::string &data) {
		std::string hash = HashWrapper::Crypto(data);
		utils::MutexGuard guard(mutex_msg_sending_);
		BroadcastRecordMap::iterator result = records_.find(hash);
		if (result == records_.end()){ // no one has sent us this message
			BroadcastRecord::pointer record = std::make_shared<BroadcastRecord>(
				type, data, 0);

			records_[hash] = record;
			records_couple_[record->time_stamp_] = hash;
			std::set<int64_t> peer_ids = driver_->GetActivePeerIds();
			for (const auto peer_id : peer_ids)
			{
				driver_->SendRequest(peer_id, type, data);
				record->peers_.insert(peer_id);
			}
		}
		else{ // send it to people that haven't sent it to us
			std::set<int64_t>& peersTold = result->second->peers_;
			for (const auto peer : driver_->GetActivePeerIds()){
				if (peersTold.find(peer) == peersTold.end())
				{
					driver_->SendRequest(peer, type, data);
					result->second->peers_.insert(peer);
				}
			}
		}
	}

	void Broadcast::OnTimer(){
		utils::MutexGuard guard(mutex_msg_sending_);
		int64_t current_time = utils::Timestamp::HighResolution();

		for (auto it = records_couple_.begin(); it != records_couple_.end();){
			// give one ledger of leeway
			if (it->first + 120 * utils::MICRO_UNITS_PER_SEC < current_time)
			{
				records_.erase(it->second);
				records_couple_.erase(it++);
			}
			else
			{
				break;
			}
		}
	}
}
