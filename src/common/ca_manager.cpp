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
#include "ca_manager.h"
#include <json/json.h>
#include <utils/strings.h>
#include <utils/file.h>
#include <utils/logger.h>
#include <utils/system.h>
#include <common/private_key.h>
#include <HttpClient.h>

namespace bubi {
	bool CAManager::RequestCA(char *file_path, char *common_name, char *organization, char *email, char *priv_password, char *hard_addr, char *node_id, char *out_msg) {
		bool bret = false;
		do {
			char err_msg[256] = { 0 };
			if (NULL == organization) {
				strcpy(out_msg, "organization cannot be empty");
				break;
			}
			if (NULL == common_name) {
				strcpy(out_msg, "common name cannot be empty");
				break;
			}
			if (NULL == email) {
				strcpy(out_msg, "email cannot be empty");
				break;
			}
			if (NULL == priv_password) {
				strcpy(out_msg, "private key password cannot be empty");
				break;
			}
			// get hardware address
			std::string hard_address = hard_addr;

			// get node id
			std::string node_address = "*";
			if (node_id != NULL) {
				std::string node_address = node_id;
			}

			bubi::stuSUBJECT subject;
			strncpy((char *)subject.O, organization, strlen(organization) > (strlen((char *)subject.O) - 1) ? (strlen((char *)subject.O) - 1) : strlen(organization));
			strncpy((char *)subject.CN, common_name, strlen(organization) > (strlen((char *)subject.CN) - 1) ? (strlen((char *)subject.CN) - 1) : strlen(organization));
			strncpy((char *)subject.MAIL, email, strlen(email) > (strlen((char *)subject.MAIL) - 1) ? (strlen((char *)subject.MAIL) - 1) : strlen(email));
			strncpy((char *)subject.HD, hard_address.c_str(), hard_address.length() > (strlen((char *)subject.HD) - 1) ? (strlen((char *)subject.HD) - 1) : hard_address.length());
			strncpy((char *)subject.NI, node_address.c_str(), node_address.length() > (strlen((char *)subject.NI) - 1) ? hard_address.length() > (strlen((char *)subject.NI) - 1) : node_address.length());

			std::string file_paths = file_path;
			if (!utils::File::IsAbsolute(file_paths)) {
				file_paths = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), file_paths.c_str());
			}

			std::string req_csr = utils::String::Format("%s/%s_%s.csr", file_paths.c_str(), common_name, organization);
			std::string priv_pem = utils::String::Format("%s/%s_%s.pem", file_paths.c_str(), common_name, organization);
			bubi::CA ca;
			if (!ca.MakeReq(&subject, 2048, req_csr.c_str(), priv_pem.c_str(), priv_password, err_msg)) {
				sprintf(out_msg, "make request certificate failed, because %s", err_msg);
				break;
			}
			printf("\nrequest file : \n  %s\nprivate file : \n  %s\n\n\n", req_csr.c_str(), priv_pem.c_str());
			if (!ShowRequestCSR((char *)req_csr.c_str(), err_msg)) {
				sprintf(out_msg, "show request certificate failed, because %s", err_msg);
				utils::File::Delete(req_csr);
				utils::File::Delete(priv_pem);
				break;
			}
			bret = true;
		} while (false);

		return bret;
	}

	bool CAManager::ShowRequestCSR(char *req_file, char *out_msg) {
		bool bret = false;
		do {
			if (NULL == req_file) {
				sprintf(out_msg, "the request file(%s) cannot not be empty", req_file);
				break;
			}
			std::string req_file_path = req_file;
			if (!utils::File::IsAbsolute(req_file_path)) {
				req_file_path = utils::String::Format("%s/config/%s", utils::File::GetBinHome().c_str(), req_file_path.c_str());
			}

			// get request certificate content
			bubi::CA ca;
			bubi::stuSUBJECT req_info;
			char err_msg[256] = { 0 };
			if (!ca.GetReqContent(req_file_path.c_str(), req_info, err_msg)) {
				sprintf(out_msg, "get request certificate info failed, %s", err_msg);
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

			printf("\nthe request certificate information:\n%s\n", results.toStyledString().c_str());
			bret = true;
		} while (false);

		return bret;
	}

	int CAManager::CheckCertificate(const std::string& node_private_key, const std::string& verify_file, const std::string& chain_file,
		const std::string& private_key_file, const std::string& private_password, const std::string& domain, const std::string& path,
		const int& port, char *serial, bool& cert_enabled, char *out_msg) {
		int iret = 0;
		do {
			char err_msg[256] = { 0 };
			// check certificate
			std::string verify_file_full = verify_file;
			if (!utils::File::IsAbsolute(verify_file_full)) {
				verify_file_full = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), verify_file_full.c_str());
			}
			std::string chain_file_full = chain_file;
			if (!utils::File::IsAbsolute(chain_file_full)) {
				chain_file_full = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), chain_file_full.c_str());
			}
			std::string priv_key_file_full = private_key_file;
			if (!utils::File::IsAbsolute(priv_key_file_full)) {
				priv_key_file_full = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), priv_key_file_full.c_str());
			}
			bubi::CA ca;
			char root_ext_code[256] = { 0 };
			if (!ca.CheckRootCert(verify_file_full.c_str(), root_ext_code, 256, err_msg)) {
				sprintf(out_msg, "this root certificate is invalid, %s", err_msg);
				break;
			}

			if (!ca.CheckEntityCert(verify_file_full.c_str(), chain_file_full.c_str(), priv_key_file_full.c_str(), private_password.c_str(), err_msg)) {
				sprintf(out_msg, "this entity certificate is invalid, %s", err_msg);
				break;
			}
			// check hardware and node id
			char hard_address[33] = { 0 };
			char node_id[50] = { 0 };
			if (!ca.GetHDAndDA(chain_file_full.c_str(), hard_address, sizeof(hard_address), node_id, sizeof(node_id), err_msg)) {
				sprintf(out_msg, "get hardware address and node id failed ,%s", err_msg);
				break;
			}
			if (strcmp(hard_address, "*") != 0) {
				utils::System system;
				std::string hard_addr;
				if (!system.GetHardwareAddress(hard_addr, err_msg)) {
					sprintf(out_msg, "get hardware address failed, %s", err_msg);
					break;
				}
				if (hard_addr.compare(hard_address) != 0) {
					sprintf(out_msg, "this user certificate is invalid in this host");
					break;
				}
			}
			if (strcmp(node_id, "*") != 0) {
				bubi::PrivateKey priv_key(node_private_key);
				std::string node_address = priv_key.GetBase16Address();
				if (node_address.compare(node_id) != 0) {
					sprintf(out_msg, "this user certificate is invalid in this node");
					break;
				}
			}
			// get serial number
			if (!ca.GetCertSerial(chain_file_full.c_str(), serial, err_msg)) {
				sprintf(out_msg, "get serial number failed, %s", err_msg);
				break;
			}

			// get cert_enabled
			if (!ca.GetCAEnabled(chain_file_full.c_str(), cert_enabled, err_msg)) {
				sprintf(out_msg, "get cert_enabled failed, %s", err_msg);
				break;
			}
			iret = 1;
		} while (false);

		return iret;
	}

	bool CAManager::VerifyCertificate(void *x509, const char *verify_file, const char * chain_file, const void *ca_lists, char *out_msg) {
		bool bret = false;
		do {
			if (NULL == x509) {
				sprintf(out_msg, "the handle of the remote certificate is null");
				break;
			}
			if (NULL == ca_lists) {
				sprintf(out_msg, "the list of certificates is null");
				break;
			}
			X509 *cert = (X509*)x509;
			const bubi::CAStatusMap* ca_list = (const bubi::CAStatusMap*)ca_lists;
			// check certificate
			bubi::CA ca;
			char serial[128] = { 0 };
			if (!ca.GetCertSerial(cert, serial, out_msg)) {
				sprintf(out_msg, "get remote certificate serial number failed");
				break;
			}
			// skip root certificate
			char out_err[256] = { 0 };
			if (0 == strcmp(serial, "01")) {
				char user_root_code[256] = { 0 };
				if (!ca.CheckRootCert(cert, user_root_code, 256, out_err)) {
					sprintf(out_msg, "check remote root certificate failed, %s", out_err);
					break;
				}
				std::string verify_file_full = verify_file;
				if (!utils::File::IsAbsolute(verify_file_full)){
					verify_file_full = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), verify_file_full.c_str());
				}
				char local_root_code[256] = { 0 };
				if (!ca.GetRootCode(verify_file_full.c_str(), local_root_code, 256, out_msg)) {
					break;
				}
				if (strcmp(user_root_code, local_root_code) != 0) {
					sprintf(out_msg, "remote root certificate's code (%s) is not same with local root certificate' code (%s)", user_root_code, local_root_code);
					break;
				}
				bret = true;
				break;
			}

			// check the entity certificate
			if (!ca.CheckCertValidity(cert, NULL, NULL, out_err)) {
				sprintf(out_msg, "check remote entity certificate failed, %s", out_err);
				break;
			}

			// check the serial number of the other side' certificate 
			char serial_number[256] = { 0 };
			if (!ca.GetCertSerial(cert, serial_number, out_msg)) {
				break;
			}

			std::string chain_file_full = chain_file;
			if (!utils::File::IsAbsolute(chain_file_full)){
				chain_file_full = utils::String::Format("%s/%s", utils::File::GetBinHome().c_str(), chain_file_full.c_str());
			}
			char local_serial_number[256] = { 0 };
			if (!ca.GetCertSerial(chain_file_full.c_str(), local_serial_number, out_msg)) {
				break;
			}

			if (strcmp(serial_number, local_serial_number) == 0) {
				sprintf(out_msg, "the remote certificate is same with local certificate");
				break;
			}
			bret = true;
		} while (false);

		return bret;
	}

	bool CAManager::GetCertificatList(const std::string& domain, const std::string& path, const int& port,
		const std::string serial_num, void *ca_lists, char *out_msg) {
		bool bret = false;
		do {
			bubi::CAStatusMap *ca_list = (bubi::CAStatusMap *)ca_lists;
			std::string path_full = "/";
			path_full = path_full + path + "/all?serial=" + serial_num;
			std::string result;
			try {
				if (http_request(domain, path_full, port, result) != 200) {
					sprintf(out_msg, "connect ca server failed, domain(%s) path(%s) port(%d)", domain.c_str(), path_full.c_str(), port);
					break;
				}
				Json::Value jresult;
				if (!jresult.fromString(result)) {
					sprintf(out_msg, "the result of certificate status is invalid");
					break;
				}
				const Json::Value& ca_items = jresult["ca"];
				for (unsigned i = 0; i < ca_items.size(); i++) {
					const Json::Value& ca_item = ca_items[i];
					bubi::stuStatus ca_status;
					ca_status.hardware_address_ = ca_item["hardware_address"].asString();
					ca_status.node_id_ = ca_item["node_id"].asString();
					ca_list->insert(std::make_pair(ca_item["id"].asString(), ca_status));
				}
				bret = true;
			}
			catch (std::exception &e) {
				sprintf(out_msg, "%s", e.what());
			}
		} while (false);

		return bret;
	}

}

