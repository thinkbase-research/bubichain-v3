#include <sqlite3.h>
#include <utils/logger.h>
#include "test.h"

int Callback(void *, int, char**, char**){
	return 0;
}

int TestSqlite3(){
	sqlite3* db;
	int ret = sqlite3_open("c:\\tmp\\sqlite3_test", &db);
	if ( ret != 0 ){
		LOG_ERROR_ERRNO("open db failed", STD_ERR_CODE, STD_ERR_DESC);
	}

	char *err = 0;
	std::string sql = "select * from test";
	ret = sqlite3_exec(db, sql.c_str(), Callback, 0, &err);
	if (ret != SQLITE_OK)
		return 1;
	else
		return 0;
}
