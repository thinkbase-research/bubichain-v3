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

#include <utils/timestamp.h>
#include <utils/logger.h>
#include "alert.h"

namespace monitor {
	Alert::Alert() {
		ResetState();
		cpu_criticality_ = 100;
		memory_criticality_ = 100;
		disk_criticality_ = 100;
		consensus_time_ = 360;
		bubi_crack_time_ = 60;
		alert_interval_ = 8 * utils::MICRO_UNITS_PER_SEC;
	}

	Alert::~Alert() {}

	bool Alert::Initialize() {
		return true;
	}

	bool Alert::Exit() {
		return true;
	}

	void Alert::ResetState() {
		buffer_.Clear();
		cpu_state_.Clear();
		memory_state_.Clear();
		consensus_state_.Clear();
		bubi_state_.Clear();
		for (uint32_t i = 0; i < disks_state_.size(); i++) {
			monitor::AlertState& disk_state = disks_state_.at(i);
			disk_state.Clear();
		}
		consensus_last_time_ = utils::Timestamp::HighResolution();
		bubi_last_time_ = consensus_last_time_;
		alert_last_time_ = bubi_last_time_;
	}

	std::string Alert::GetId() {
		utils::MutexGuard guard_id(mutex_id_);
		return id_;
	}

	bool Alert::GetBubiCrackState() {
		bool bret = false;
		if (bubi_state_.alert_state() == monitor::AlertState::NONE) {
			bret = true;
		}
		return bret;
	}

	void Alert::SetBuffer(const monitor::ChainAlertMessage &buffer) {
		utils::MutexGuard guard_buffer(mutex_buffer_);
		buffer_.CopyFrom(buffer);
	}

	void Alert::SetCpuCriticality(const double cpu_criticality) {
		cpu_criticality_ = cpu_criticality;
	}

	void Alert::SetMemoryCriticality(const double memory_criticality) {
		memory_criticality_ = memory_criticality;
	}

	void Alert::SetDiskCriticality(const double disk_criticality) {
		disk_criticality_ = disk_criticality;
	}

	void Alert::SetConsensusTime(const uint64_t consensus_time) {
		consensus_time_ = consensus_time;
	}

	void Alert::SetBubiCrackTime(const uint64_t bubi_crack_time) {
		bubi_crack_time_ = bubi_crack_time;
	}

	void Alert::SetBubiLastTime(uint64_t bubi_last_time) {
		bubi_last_time_ = bubi_last_time;
	}

	bool Alert::CheckBubiState() {
		bool bwarning = false;
		uint64_t high_resolution_time = utils::Timestamp::HighResolution();
		monitor::ChainAlertMessage buffer;
		{
			utils::MutexGuard guard_buffer(mutex_buffer_);
			buffer.CopyFrom(buffer_);
		}
		if ((bubi_state_.alert_state() == monitor::AlertState::NOWARNING || bubi_state_.alert_state() == monitor::AlertState::NONE) &&
			(high_resolution_time - bubi_last_time_ > bubi_crack_time_ * utils::MICRO_UNITS_PER_SEC)) {
			bubi_state_.set_alert_state(monitor::AlertState::WARNING);
			bubi_state_.set_description("bubi");
			bwarning = true;
		}
		else if ((bubi_state_.alert_state() == monitor::AlertState::WARNING || bubi_state_.value() > 1e+7) &&
			(high_resolution_time - bubi_last_time_ < bubi_crack_time_ * utils::MICRO_UNITS_PER_SEC) && buffer.has_system()) {
			bubi_state_.set_alert_state(monitor::AlertState::NOWARNING);
			bubi_state_.set_description("bubi");
			bwarning = true;
		}
		return bwarning;
	}

	bool Alert::CheckConsensusState(const uint64_t& ledger_sequence) {
		bool bwarning = false;
		do {
			uint64_t high_resolution_time = utils::Timestamp::HighResolution();
			monitor::ChainAlertMessage buffer;
			{
				utils::MutexGuard guard_buffer(mutex_buffer_);
				buffer.CopyFrom(buffer_);
			}
			if ((consensus_state_.alert_state() == monitor::AlertState::NONE || consensus_state_.alert_state() == monitor::AlertState::NOWARNING) &&
				(high_resolution_time - consensus_last_time_ > consensus_time_ * utils::MICRO_UNITS_PER_SEC) &&
				(consensus_state_.value() >= ledger_sequence) && buffer.has_system()) {
				consensus_state_.set_value((double)ledger_sequence);
				consensus_state_.set_alert_state(monitor::AlertState::WARNING);
				consensus_state_.set_description("consensus");
				consensus_last_time_ = high_resolution_time;
				bwarning = true;
			}
			else if ((consensus_state_.alert_state() == monitor::AlertState::NONE || consensus_state_.alert_state() == monitor::AlertState::WARNING) &&
				(consensus_state_.value() < ledger_sequence) && buffer.has_system()) {
				consensus_state_.set_value((double)ledger_sequence);
				consensus_state_.set_alert_state(monitor::AlertState::NOWARNING);
				consensus_state_.set_description("consensus");
				consensus_last_time_ = high_resolution_time;
				bwarning = true;
			}
		} while (false);
		return bwarning;
	}

	bool Alert::CheckCpuWarning(const double& cpu_used_percent) {
		bool bwarning = false;
		if (cpu_state_.alert_state() == monitor::AlertState::WARNING || cpu_state_.alert_state() == monitor::AlertState::NOWARNING) {
			if (cpu_used_percent >= cpu_criticality_) {
				cpu_state_.set_value(cpu_used_percent);
				cpu_state_.set_alert_state(monitor::AlertState::WARNING);
				cpu_state_.set_description("cpu");
				bwarning = true;
			}
		}
		else if (cpu_state_.alert_state() == monitor::AlertState::WARNING || cpu_state_.alert_state() == monitor::AlertState::WARNING) {
			if (cpu_used_percent < cpu_criticality_) {
				cpu_state_.set_value(cpu_used_percent);
				cpu_state_.set_alert_state(monitor::AlertState::NOWARNING);
				cpu_state_.set_description("cpu");
				bwarning = true;
			}
		}
		return bwarning;
	}

	bool Alert::CheckMemoryWarning(const double& usage_percent) {
		bool bwarning = false;
		if (memory_state_.alert_state() == monitor::AlertState::WARNING || memory_state_.alert_state() == monitor::AlertState::NOWARNING) {
			if (usage_percent >= memory_criticality_) {
				memory_state_.set_value(usage_percent);
				memory_state_.set_alert_state(monitor::AlertState::WARNING);
				memory_state_.set_description("memory");
				bwarning = true;
			}
		}
		else if (memory_state_.alert_state() == monitor::AlertState::WARNING || memory_state_.alert_state() == monitor::AlertState::WARNING) {
			if (usage_percent < memory_criticality_) {
				memory_state_.set_value(usage_percent);
				memory_state_.set_alert_state(monitor::AlertState::NOWARNING);
				memory_state_.set_description("memory");
				bwarning = true;
			}
		}
		return bwarning;
	}


	bool Alert::CheckDiskWarning(const Partition& partitions, std::vector<monitor::AlertState>& disks_state_changed) {
		bool bwarning = false;
		for (uint32_t i = 0; i < disks_state_.size(); i++) {
			monitor::AlertState& disk_state = disks_state_.at(i);
			for (int j = 0; j < partitions.partition_size(); j++) {
				const monitor::SystemResource& part = partitions.partition(j);
				if (part.description().compare(disk_state.description()) == 0) {
					if (disk_state.alert_state() == monitor::AlertState::WARNING || disk_state.alert_state() == monitor::AlertState::NOWARNING) {
						if (part.usedpercent() >= disk_criticality_) {
							disk_state.set_value(part.usedpercent());
							disk_state.set_alert_state(monitor::AlertState::WARNING);
							disk_state.set_description(part.description());
							disks_state_changed.push_back(disk_state);
							bwarning = true;
						}
					}
					else if (disk_state.alert_state() == monitor::AlertState::WARNING || disk_state.alert_state() == monitor::AlertState::WARNING) {
						if (part.usedpercent() < disk_criticality_) {
							disk_state.set_value(part.usedpercent());
							disk_state.set_alert_state(monitor::AlertState::NOWARNING);
							disk_state.set_description(part.description());
							disks_state_changed.push_back(disk_state);
							bwarning = true;
						}
					}
				}
			}
			
			
		}
		return bwarning;
	}

	bool Alert::CheckAlert(monitor::AlertStatus& items) {
		bool bwarning = false;
		int64_t high_resolution_time = utils::Timestamp::HighResolution();
		if (high_resolution_time - alert_interval_ > alert_last_time_) {
			do {
				uint64_t ledger_sequence = 0;
				double cpu_used_percent = 0;
				double memory_used_percent = 0;
				monitor::ChainAlertMessage buffer;
				{
					utils::MutexGuard guard_buffer(mutex_buffer_);
					buffer.CopyFrom(buffer_);
				}
				if (buffer.has_system()) {
					if (buffer.node_id().empty()) {
						LOG_ERROR("Alert on_alert_method : bubi version is low");
						break;
					}
					{
						utils::MutexGuard guard_id(mutex_id_);
						id_ = buffer.node_id();
					}

					ledger_sequence = buffer.ledger_sequence();
					cpu_used_percent = buffer.system().cpu().usedpercent();
					memory_used_percent = buffer.system().memory().usedpercent();
				}

				if (CheckBubiState()) {
					monitor::AlertState* bubi_state = items.add_alert_state();
					bubi_state->CopyFrom(bubi_state_);
					bwarning = true;
				}

				if (CheckConsensusState(ledger_sequence)) {
					monitor::AlertState* consensus_state = items.add_alert_state();
					consensus_state->CopyFrom(consensus_state_);
					bwarning = true;
				}

				if (CheckCpuWarning(cpu_used_percent)) {
					monitor::AlertState* cpu_state = items.add_alert_state();
					cpu_state->CopyFrom(cpu_state_);
					bwarning = true;
				}

				if (CheckMemoryWarning(memory_used_percent)) {
					LOG_INFO("memory monitor::AlertState::WARNING  total=%lld, avail=%lld", buffer.system().memory().total(), buffer.system().memory().available());
					monitor::AlertState* memory_state = items.add_alert_state();
					memory_state->CopyFrom(memory_state_);
					bwarning = true;
				}

				std::vector<monitor::AlertState> disks_state_changed;
				const monitor::Partition& parts = buffer.system().partitions();
				if (CheckDiskWarning(parts, disks_state_changed)) {
					for (uint32_t i = 0; i < disks_state_changed.size(); i++) {
						for (int j = 0; j < parts.partition_size(); j++) {
							if (disks_state_changed[i].description().compare(parts.partition(j).description()) == 0) {
								LOG_INFO("disk monitor::AlertState::WARNING describ=%s, total=%lld, avail=%lld", parts.partition(j).description().c_str(),
									parts.partition(j).total(), parts.partition(j).available());
								monitor::AlertState* disk_state = items.add_alert_state();
								disk_state->CopyFrom(disks_state_changed[i]);
							}
						}
						
					}
					bwarning = true;
				}

			} while (false);
			alert_last_time_ = high_resolution_time;
		}

		return bwarning;
	}

}