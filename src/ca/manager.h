#pragma once

#include <utils/ca.h>

namespace bubi_ca {
	class Manager {
	public:
		// make root certificate
		bool MakeRoot(void *rootInfo, int days, const char *cert_file, const char *pri_file, const char *password, char *out, int type = PEM);

		// get root code
		bool GetRootCode(const char *root_cert_file, char *root_code, int len, char *out_msg);

		// show request certificate
		bool ShowRequestCSR(char *req_file, char *out_msg);

		// make end entity certificate
		bool MakeEntity(char *root_ca_file, char *root_private_file, char *root_private_password, char *request_file, int days, int ca_enabled, char *out_msg);
	};
}