#include <json/json.h>
#include <utils/logger.h>
#include "test.h"

void TestJson(){
	std::string text = "{\"a\":[1,2,3,4], \"b\":\"bubi the json\"}";
	Json::Value jsonvalue;
	Json::Reader reader;
	if (!reader.parse(text, jsonvalue)){
		LOG_ERROR("Json parse string(%s) error ", text.c_str());
	}

	std::string bubis = jsonvalue["b"].asString();
	Json::Value jsonarray = jsonvalue["a"];
	LOG_INFO("json string %s, array size:" FMT_SIZE, bubis.c_str(), jsonarray.size());
}

