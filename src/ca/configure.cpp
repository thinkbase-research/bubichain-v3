#include <utils/utils.h>
#include <utils/file.h>
#include <utils/strings.h>
#include <utils/logger.h>
#include <common/general.h>
#include "configure.h"

namespace bubi {
	CARoot::CARoot() : days_(0) {}

	CARoot::~CARoot() {}


	bool CARoot::Load(const Json::Value &value) {
		Configure::GetValue(value, "file_name", file_name_);
		Configure::GetValue(value, "common_name", common_name_);
		Configure::GetValue(value, "organization", organization_);
		Configure::GetValue(value, "email", email_);
		Configure::GetValue(value, "domain", domain_);
		Configure::GetValue(value, "days", days_);
		Configure::GetValue(value, "private_password", private_password_);
		private_password_ = utils::Aes::HexDecrypto(private_password_, bubi::GetDataSecuretKey());
		return true;
	}

	CAEntity::CAEntity() : days_(0) {}

	CAEntity::~CAEntity() {}

	bool CAEntity::Load(const Json::Value &value) {
		Configure::GetValue(value, "db_server", db_server_);
		Configure::GetValue(value, "request_file", request_file_);
		Configure::GetValue(value, "root_private_file", root_private_file_);
		Configure::GetValue(value, "root_private_password", root_private_password_);
		root_private_password_ = utils::Aes::HexDecrypto(root_private_password_, bubi::GetDataSecuretKey());
		Configure::GetValue(value, "root_ca_file", root_ca_file_);
		Configure::GetValue(value, "days", days_);
		Configure::GetValue(value, "ca_enable", ca_enable_);

		return true;
	}

	Configure::Configure() {}

	Configure::~Configure() {}

	bool Configure::LoadFromJson(const Json::Value &values){
		ca_root_configure_.Load(values["root"]);
		ca_entity_configure_.Load(values["entity"]);
		logger_configure_.Load(values["logger"]);
		return true;
	}
}