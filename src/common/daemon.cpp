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
#include "daemon.h"

namespace utils {
	Daemon::Daemon() {
		last_write_time_ = 0;
		timer_name_ = "Daemon";
		shared = NULL;
	}

	Daemon::~Daemon() {}

	//void Daemon::GetModuleStatus(Json::Value &data) const {
	//}

	bool Daemon::Initialize(int32_t key) {
		bubi::TimerNotify::RegisterModule(this);
#ifdef WIN32

#else
		//互斥锁初始化
		int fd;
		pthread_mutexattr_t mattr;
		fd = open("/dev/zero", O_RDWR, 0);
		mptr = (pthread_mutex_t*)mmap(0, sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		close(fd);
		pthread_mutexattr_init(&mattr);
		pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init(mptr, &mattr);

		//创建共享内存
		shmid = shmget((key_t)key, sizeof(int64_t), 0666 | IPC_CREAT);
		if (shmid == -1) {
			LOG_ERROR("shmget failed");
			return true;
		}
		//将共享内存连接到当前进程的地址空间
		shm = shmat(shmid, (void*)0, 0);
		if (shm == (void*)-1) {
			LOG_ERROR("shmat failed\n");
			return false;
		}
		LOG_INFO("Memory attached at %lx\n", (unsigned long int)shm);
		//设置共享内存
		shared = (int64_t*)shm;

#endif
		return true;
	}

	bool Daemon::Exit() {
#ifdef WIN32
#else
		//把共享内存从当前进程中分离
		if (shmdt(shm) == -1) {
			LOG_ERROR("shmdt failed");
			return false;
		}
		return true;
#endif
		return true;
	}

	void Daemon::OnTimer(int64_t current_time) {
		//int64_t now_time = utils::Timestamp::GetLocalTimestamp(,);
		//int64_t now_time = utils::Timestamp::Now().timestamp();
#ifdef WIN32
#else
		if (current_time - last_write_time_ > 500000) {
			pthread_mutex_lock(mptr);
			if (shared) *shared = current_time;
			last_write_time_ = current_time;
			pthread_mutex_unlock(mptr);
		}
#endif
	}

	void Daemon::OnSlowTimer(int64_t current_time) {

	}
}