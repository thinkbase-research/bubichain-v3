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

#ifndef BROADCAST_H_
#define BROADCAST_H_

namespace bubi{

	class IBroadcastDriver{
	public:
		IBroadcastDriver(){};
		virtual ~IBroadcastDriver(){};

		//virtual bool SendMessage(int64_t peer_id, WsMessagePointer msg) = 0;
		virtual bool SendRequest(int64_t peer_id, int64_t type, const std::string &data) = 0;
		virtual std::set<int64_t> GetActivePeerIds() = 0;
	};

	class BroadcastRecord{
	public:
		typedef std::shared_ptr<BroadcastRecord> pointer;

		BroadcastRecord(int64_t type, const std::string &data, int64_t);
		~BroadcastRecord();

		int64_t type_;
		std::string data_;
		int64_t time_stamp_;
		std::set<int64_t> peers_;
	};

	typedef std::map<int64_t, std::string> BroadcastRecordCoupleMap;
	typedef std::map<std::string, BroadcastRecord::pointer> BroadcastRecordMap;

	class Broadcast {
	private:
		BroadcastRecordCoupleMap    records_couple_;
		BroadcastRecordMap records_;
		utils::Mutex mutex_msg_sending_;
		IBroadcastDriver *driver_;

	public:
		Broadcast(IBroadcastDriver *driver);
		~Broadcast();

		bool Add(int64_t type, const std::string &data, int64_t peer_id);
		void Send(int64_t type, const std::string &data);
		void OnTimer();
		size_t GetRecordSize() const { return records_.size(); };
	};
};

#endif