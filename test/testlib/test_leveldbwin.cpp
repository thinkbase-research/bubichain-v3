#include <leveldb/leveldb.h>
#include <utils/logger.h>
#include <utils/Timestamp.h>
#include "test.h"

void WriteDb(leveldb::DB* db)
{
	const char* Content = "We now decided that after three years it might"
		" be a good idea to re-assess our current situation by another,"
		" more extensive survey. It is similar to the original one "
		"(since we included the old questions to be able to compare the results),"
		" but the survey also contains a bunch of new ones to take new developments"
		" such as Ogre usage on mobile devices into account.";
	char Buff[10];
	memset(Buff, 0,sizeof(Buff));
	leveldb::WriteOptions wo;
	wo.sync = false;
	for (int i = 0; i < 2000; i++){
		_itoa_s(i, Buff, 10);

		leveldb::Status s = db->Put(wo, Buff, Content);
	}
}

void ReadDb(leveldb::DB* db)
{
	leveldb::ReadOptions ro;
	char Buff[10];
	memset(Buff, 0, sizeof(Buff));
	std::string value__;
	for (int i = 0; i < 2000; i++){
		_itoa_s(i, Buff, 10);
		leveldb::Status s = db->Get(ro, Buff, &value__);
	}
}

void tt()
{
	leveldb::DB* db = NULL;
	leveldb::Options options;
	options.create_if_missing = true;
	options.write_buffer_size = 8 * 1024 * 1024;
	leveldb::Status status = leveldb::DB::Open(options, "c:/tmp/testdb", &db);
	assert(status.ok());

	//
	char buffer_1[] = {0x00,0x00,0x11,0x12};
	char key[] = "key1";

	leveldb::WriteOptions wo;
	wo.sync = false;
	leveldb::Status s = db->Put(wo, key, buffer_1);


	{
		int64_t tickbegin = utils::Timestamp::HighResolution();
		WriteDb(db);
		int64_t tickend = utils::Timestamp::HighResolution();
		LOG_INFO("write 2000 in " FMT_I64 " Milliseconds", tickend - tickbegin);
	};
	{
		int64_t tickbegin = utils::Timestamp::HighResolution();
		ReadDb(db);
		int64_t tickend = utils::Timestamp::HighResolution();
		LOG_INFO("read 2000 in " FMT_I64 " Milliseconds", tickend - tickbegin);
	};
	delete db;
}

int TestLevelDbWin()
{
	int repeat = 100;
	for (int i = 0; i < repeat; i++){
		tt();
	}
	LOG_INFO("%d times done", repeat);
	return getchar();
}
