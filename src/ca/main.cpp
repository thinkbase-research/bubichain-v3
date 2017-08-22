#include <common/ca_manager.h>
#include <common/general.h>
#include <utils/file.h>
#include "manager.h"

void Usage();

int main(int argc, char** argv) {
	do {
		int common_type = 0;
		if (argc > 1) {
			std::string s(argv[1]);
			if (s == "--version") {
				common_type = 0;
			}
			else if (s == "--root") {
				common_type = 1;
			}
			else if (s == "--root-code") {
				common_type = 2;
			}
			else if (s == "--show-request") {
				common_type = 3;
			}
			else if (s == "--entity") {
				common_type = 4;
			}
			else if (s == "--help"){
				Usage();
				return 0;
			}
			else {
				Usage();
				return 0;
			}
		}
		else {
			Usage();
		}

		// command
		switch (common_type) {
		case 0:
			printf("3.0.0.0\n");
			break;
		case 1: {
					if (argc < 9) {
						printf("error: missing parameter, need 7 parameter (root_file_path, root_file_name, common_name, email, domain, days, private_password)\n");
						break;
					}
					if (!utils::String::is_number(argv[7])) {
						printf("error: days must be number \n");
						break;
					}
					utils::stuSUBJECT subject;
					std::string file_name = argv[3];
					std::string file_path = argv[2];
					file_path = file_path + "/" + file_name;
					if (!utils::File::IsAbsolute(file_path)){
						file_path = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), file_path.c_str());
					}
					std::string root_ca_path = utils::String::Format("%s.crt", file_path.c_str());
					std::string root_priv_path = utils::String::Format("%s.pem", file_path.c_str());
					strcpy((char*)subject.CN, argv[4]);
					strcpy((char*)subject.O, "布比(北京)网络技术有限公司");
					strcpy((char*)subject.MAIL, argv[5]);
					strcpy((char*)subject.OU, argv[6]);
					int days = atoi(argv[7]);
					char out_msg[256] = { 0 };
					bubi_ca::Manager ca;
					std::string private_password = argv[8];
					if (!ca.MakeRoot(&subject, days, root_ca_path.c_str(), root_priv_path.c_str(), private_password.c_str(), out_msg)) {
						printf("error: %s\n", out_msg);
					}
			}
			break;
		case 2: {
					if (argc < 3) {
						printf("error: missing parameter, need 1 parameter (root_file_path)\n");
						break;
					}
					bubi_ca::Manager ca;
					char root_code[256] = { 0 };
					char out_msg[256] = { 0 };
					if (!ca.GetRootCode(argv[2], root_code, 256, out_msg)) {
						printf("error: %s\n", out_msg);
					}
					else {
						printf("root code: %s\n", root_code);
					}
			}
			break;
		case 3: {
					if (argc < 3) {
						LOG_ERROR("missing parameter, need 1 parameter (request_file_path)");
						break;
					}
					bubi_ca::Manager ca;
					char out_msg[256] = { 0 };
					if (!ca.ShowRequestCSR(argv[2], out_msg)) {
						printf("error: %s\n", out_msg);
					}
			}
			break;
		case 4: {
					if (argc < 3) {
						printf("error: missing parameter, need 6 parameter (root_ca_file_path, root_private_file_path, root_private_password, request_file_path, days, ca_enable(must be number, 1 or 0)\n");
						break;
					}
					if (!utils::String::is_number(argv[6])) {
						printf("error: days must be number \n");
						break;
					}
					if (!utils::String::is_number(argv[7])) {
						printf("error: ca_enable must be number \n");
						break;
					}
					int ca_enable = atoi(argv[7]);
					if (ca_enable != 1 && ca_enable != 0) {
						printf("error: ca_enable must be 1 or 0\n");
						break;
					}
					bubi_ca::Manager ca;
					char out_msg[256] = { 0 };
					if (!ca.MakeEntity(argv[2], argv[3], argv[4], argv[5], atoi(argv[6]), ca_enable, out_msg)) {
						printf("error: %s\n", out_msg);
					}
			}
			break;
		
		}
	} while (false);
	
	
	
	return 0;
}

void Usage(){
	printf(
		"Usage: bubi_ca [OPTIONS]\n"
		"OPTIONS:\n"
		"  --show-request                  show request ca certificate\n"
		"  --root                          make root certificate\n"
		"  --root-code                     show the code of root certificate\n"
		"  --entity                        make entity certificate\n"
		"  --version                       display version information\n"
		"  --help                          display this help\n"
		);
}