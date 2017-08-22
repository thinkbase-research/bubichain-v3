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

#ifndef TEST_SQLPARSER_H_
#define TEST_SQLPARSER_H_

#include "strings.h"

namespace utils{
	class SqlParser{
		std::string query_type_;
		std::string raw_sql_;
		std::string table_;
		std::string fields_;
		std::string condition_;
		std::string limit_;
		std::string orderby_;
		std::string groupby_;
		//utils::StringMap fields_;
		std::string error_desc_;
		std::string db_name_;

		std::string find_command_;
		std::string mongo_count_;
		std::string mongo_where_;
		std::string mongo_distinct_;
		std::string mongo_field_;
		std::string mongo_skip_;
		std::string mongo_limit_;
		std::string mongo_orderby_;
		std::string mongo_groupby_;
		utils::StringVector fields_vec_;
		std::string mongo_statement_;
		uint32_t limit_int_;
		uint32_t skip_int_;

		utils::StringMap indexes_;
		std::string null_string;

		void Clear();
	public:
		SqlParser();
		~SqlParser();

	public:
		bool Parse(const std::string &sql);
		bool ParseCreateTable(std::string &result);
		bool ParseCreateDatabase(std::string &result);
		bool ParseDropDatabase(std::string &result);
		bool ParseDelete(std::string &result);
		bool ParseSelect(std::string &result);
		bool ParseUpdate(std::string &result);
		bool ParseInsert(std::string &result);

		bool ParseGroupBy(const std::string &groupby);
		bool ParseField(const std::string &field);
		bool ParseTable(const std::string &table);
		std::string  ParseWhere(const std::string &sql_where);
		bool Equation2Mg(const std::string &item, std::string &equaltion);
		bool ParseOrderBy(const std::string &item, std::string &mongo_sort);
		bool ParseLimit(const std::string &item, std::string &mongo_limit);
		const std::string &mg_statement() const;
		const std::string &error_desc() const;
		const std::string &mg_field() const;
		const std::string &mg_groupby() const;
		const std::string &mg_condition() const;
		const std::string &mg_table() const;
		const std::string &mg_orderby() const;
		uint32_t limit() const;
		uint32_t skip() const;
		const std::string &query_type() const;
		const utils::StringMap &indexes() const;
		const std::string &db_name() const;
	};
}
#endif