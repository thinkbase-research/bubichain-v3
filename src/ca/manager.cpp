#include <utils/headers.h>
#include <json/json.h>
#include <common/general.h>
#include "manager.h"

namespace bubi_ca {
	bool Manager::MakeRoot(void *root_info, int days, const char *cert_file, const char *pri_file, const char *password, char *out_msg, int type) {
		bool bret = false;
		RSA *rsa = NULL;
		EVP_PKEY * pkey = NULL;
		X509 *x509 = NULL;
		BIO *bcert = NULL, *bkey = NULL;
		do {
			if (days <= 30) {
				sprintf(out_msg, "days must bigger than 30");
				break;
			}

			if (((bcert = BIO_new_file(cert_file, "w+")) == NULL) || ((bkey = BIO_new_file(pri_file, "w+")) == NULL)) {
				sprintf(out_msg, "Create File(%s) Error", cert_file);
				break;
			}
			utils::CA ca;
			utils::stuSUBJECT *root_subject = (utils::stuSUBJECT *)root_info;
			if (!ca.mkRoot(root_subject, &x509, &rsa, &pkey, 2048, days, out_msg)) {
				break;
			}
			int i = 0, j = 0;
			switch (type) {
			case DER: {
					i = i2d_X509_bio(bcert, x509);
					j = i2d_RSAPrivateKey_bio(bkey, rsa);
				}
				break;
			case PEM: {
					i = PEM_write_bio_X509(bcert, x509);
					j = PEM_write_bio_RSAPrivateKey(bkey, rsa, EVP_des_ede3_cbc(), (unsigned char*)password, strlen(password), NULL, NULL);
				}
				break;
			default:
				break;
			}
			if (0 == i || 0 == j) {
				sprintf(out_msg, "save certificate(%s) or key(%s) file error", cert_file, pri_file);
			}

			printf("\n\nroot certificate file: \n  %s\nprivate file: \n  %s\n\n\n", cert_file, pri_file);
			bret = true;
		} while (false);
		if (bcert) BIO_free(bcert);
		if (bkey) BIO_free(bkey);
		if (x509) X509_free(x509);
		if (pkey) EVP_PKEY_free(pkey);
		return bret;
	}

	bool Manager::GetRootCode(const char *root_cert_file, char *root_code, int len, char *out_msg) {
		bool bret = false;
		do {
			if (NULL == root_cert_file) {
				sprintf(out_msg, "the certificate file cannot not be empty");
				break;
			}
			std::string root_cert_file_path = root_cert_file;
			if (!utils::File::IsAbsolute(root_cert_file_path)){
				root_cert_file_path = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), root_cert_file_path.c_str());
			}

			utils::CA ca;
			if (!ca.GetRootCode(root_cert_file_path.c_str(), root_code, len, out_msg)) {
				break;
			}
			bret = true;
		} while (false);
		
		return bret;
	}

	bool Manager::ShowRequestCSR(char *req_file, char *out_msg) {
		bool bret = false;
		do {
			if (NULL == req_file) {
				sprintf(out_msg, "the request file cannot not be empty");
				break;
			}
			std::string req_file_path = req_file;
			if (!utils::File::IsAbsolute(req_file_path)){
				req_file_path = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), req_file_path.c_str());
			}
			// get request certificate content
			utils::CA ca;
			utils::stuSUBJECT req_info;
			if (!ca.GetReqContent(req_file_path.c_str(), req_info, out_msg)) {
				break;
			}
			// print result
			Json::Value results;
			Json::Value& result_ca = results["ca"];
			Json::Value& subject = result_ca["subject"];
			if (strlen((char *)req_info.C) != 0)
				subject["country"] = (char *)req_info.C;
			if (strlen((char *)req_info.ST) != 0)
				subject["province"] = (char *)req_info.ST;
			if (strlen((char *)req_info.L) != 0)
				subject["locality"] = (char *)req_info.L;
			subject["organization"] = (char *)req_info.O;
			if (strlen((char *)req_info.OU) != 0)
				subject["organization_unit"] = (char *)req_info.OU;
			subject["common_name"] = (char *)req_info.CN;
			subject["email"] = (char *)req_info.MAIL;
			if (strlen((char *)req_info.T) != 0)
				subject["title"] = (char *)req_info.T;

			Json::Value& ext = result_ca["extensions"];
			ext["hardware_address"] = (char *)req_info.HD;
			ext["node_id"] = (char *)req_info.NI;

			printf("\n\nthe request certificate information:\n%s\n\n", results.toStyledString().c_str());
			bret = true;
		} while (false);

		return bret;
	}

	bool Manager::MakeEntity(char *root_ca_file, char *root_private_file, char *root_private_password, char *request_file, int days, int ca_enabled, char *out_msg) {
		bool bret = false;
		do {
			if (days <= 30) {
				sprintf(out_msg, "days must bigger than 30");
				break;
			}

			// check root certificate
			utils::CA ca;
			std::string root_private_pem = root_private_file;
			if (!utils::File::IsAbsolute(root_private_pem)){
				root_private_pem = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), root_private_pem.c_str());
			}
			std::string root_ca_crt = root_ca_file;
			if (!utils::File::IsAbsolute(root_ca_crt)){
				root_ca_crt = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), root_ca_crt.c_str());
			}

			char user_root_code[256] = { 0 };
			char szmsg[256] = { 0 };
			if (!ca.CheckRootCert(root_ca_crt.c_str(), user_root_code, sizeof(user_root_code), szmsg)) {
				sprintf(out_msg, "check root certificate failed, %s", szmsg);
				break;
			}

			bool ca_enable = ca_enabled ? true : false;
			std::string request_csrs = request_file;
			utils::StringVector requests = utils::String::split(request_csrs, ";");
			unsigned i = 0;
			for (; i < requests.size(); i++) {
				std::string request_csr = requests.at(i);
				if (!utils::File::IsAbsolute(request_csr)){
					request_csr = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), request_csr.c_str());
				}
				std::string user_ca_crt = request_csr.substr(0, request_csr.rfind(".")) + ".crt";
				int cn_len = 0;
				utils::stuKEYUSAGE key_usage;
				utils::stuEKEYUSAGE ekey_usage;
				char serial[128] = { 0 };
				char common_name[24] = { 0 };
				char organization[96] = { 0 };
				char email[48] = { 0 };
				std::string private_password = root_private_password;
				if (!ca.MakeCert(root_ca_crt.c_str(), root_private_pem.c_str(), private_password.c_str(), NULL, days, request_csr.c_str(),
					&key_usage, &ekey_usage, user_ca_crt.c_str(), ca_enable, serial, common_name, sizeof(common_name),
					organization, sizeof(organization), email, sizeof(email), szmsg)) {
					sprintf(out_msg, "make ca certificate failed, because %s", szmsg);
					//db.Close();
					break;
				}

				// get hardware address and node id
				char hard_address[33] = { 0 };
				char node_id[50] = { 0 };
				if (!ca.GetHDAndDA(request_csr.c_str(), hard_address, sizeof(hard_address), node_id, sizeof(node_id), szmsg)) {
					sprintf(out_msg, "get hardware address and node id failed, because %s", szmsg);
					//db.Close();
					break;
				}
				printf("\n\nmake user certificate successfully\nuser certificate file: %s\n\n\n", user_ca_crt.c_str());
			}

			if (i != requests.size()) {
				break;
			}
			bret = true;
		} while (false);
		return bret;
	}
}

