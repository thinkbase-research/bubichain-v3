#ifndef CONFIGURE_H_
#define CONFIGURE_H_

#include <common/configure_base.h>

namespace bubi {

	class CARoot {
	public:
		CARoot();
		~CARoot();

		std::string file_name_;
		std::string common_name_;
		std::string organization_;
		std::string email_;
		std::string domain_;
		uint32_t days_;
		std::string private_password_;

		bool Load(const Json::Value &value);
	};

	class CAEntity {
	public:
		CAEntity();
		~CAEntity();

		std::string db_server_;
		std::string request_file_;
		std::string root_private_file_;
		std::string root_private_password_;
		std::string root_ca_file_;
		uint32_t days_;
		bool ca_enable_;

		bool Load(const Json::Value &value);
	};

	class Configure : public ConfigureBase, public utils::Singleton<Configure> {
		friend class utils::Singleton<Configure>;
		Configure();
		~Configure();

	public:

		CARoot ca_root_configure_;
		CAEntity ca_entity_configure_;
		LoggerConfigure logger_configure_;

		virtual bool LoadFromJson(const Json::Value &values);
	};
}

#endif