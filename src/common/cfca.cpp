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

#include <openssl/ripemd.h>
#include <utils/headers.h>
#include <utils/sm3.h>

#include "cfca.h"

namespace cfca {
	bool CFCA::Initialize() {
		bool bret = false;
		do {

			std::string path = utils::File::GetBinDirecotry();
#ifdef _WIN32
#ifdef _WIN64 
			path += "/SADK.Standard.x64.dll";
			handle_ = ::LoadLibraryA(path.c_str());
#else
			path += "/SADK.Standard.x86.dll";
			handle_ = ::LoadLibraryA(path.c_str());

#endif
#define UtilGetProcAddress GetProcAddress
#else
#define  UtilGetProcAddress dlsym
			path += "/libSADK_Standard.so";
			handle_ = dlopen(path.c_str(), RTLD_NOW);
#endif
			if (!handle_){
				LOG_ERROR_ERRNO("Open cfca lib failed,path(%s)", path.c_str(), STD_ERR_CODE, STD_ERR_DESC);
				break;
			}

			cfca_functions_.Initialize = (InitializePtr)UtilGetProcAddress(handle_, "Initialize");
			cfca_functions_.Uninitialize = (UninitializePtr)UtilGetProcAddress(handle_, "Uninitialize");
			cfca_functions_.SignData_PKCS1 = (SignData_PKCS1Ptr)UtilGetProcAddress(handle_, "SignData_PKCS1");
			cfca_functions_.SignData_PKCS7Detached = (SignData_PKCS7DetachedPtr)UtilGetProcAddress(handle_, "SignData_PKCS7Detached");
			cfca_functions_.SignData_PKCS7Attached = (SignData_PKCS7AttachedPtr)UtilGetProcAddress(handle_, "SignData_PKCS7Attached");
			cfca_functions_.SignFile_PKCS7Detached = (SignFile_PKCS7DetachedPtr)UtilGetProcAddress(handle_, "SignFile_PKCS7Detached");
			cfca_functions_.VerifyDataSignature_PKCS1 = (VerifyDataSignature_PKCS1Ptr)UtilGetProcAddress(handle_, "VerifyDataSignature_PKCS1");
			cfca_functions_.VerifyDataSignature_PKCS7Detached = (VerifyDataSignature_PKCS7DetachedPtr)UtilGetProcAddress(handle_, "VerifyDataSignature_PKCS7Detached");
			cfca_functions_.VerifyDataSignature_PKCS7Attached = (VerifyDataSignature_PKCS7AttachedPtr)UtilGetProcAddress(handle_, "VerifyDataSignature_PKCS7Attached");
			cfca_functions_.VerifyFileSignature_PKCS7Detached = (VerifyFileSignature_PKCS7DetachedPtr)UtilGetProcAddress(handle_, "VerifyFileSignature_PKCS7Detached");
			cfca_functions_.EncryptDataToCMSEnvelope = (EncryptDataToCMSEnvelopePtr)UtilGetProcAddress(handle_, "EncryptDataToCMSEnvelope");
			cfca_functions_.SignAndEncryptData = (SignAndEncryptDataPtr)UtilGetProcAddress(handle_, "SignAndEncryptData");
			cfca_functions_.DecryptDataFromCMSEnvelope = (DecryptDataFromCMSEnvelopePtr)UtilGetProcAddress(handle_, "DecryptDataFromCMSEnvelope");
			cfca_functions_.DecryptAndVerifyDataSignature = (DecryptAndVerifyDataSignaturePtr)UtilGetProcAddress(handle_, "DecryptAndVerifyDataSignature");
			cfca_functions_.GetCertificateInfo = (GetCertificateInfoPtr)UtilGetProcAddress(handle_, "GetCertificateInfo");
			cfca_functions_.GetPublicCertFromPFX = (GetPublicCertFromPFXPtr)UtilGetProcAddress(handle_, "GetPublicCertFromPFX");
			cfca_functions_.VerifyCertificate = (VerifyCertificatePtr)UtilGetProcAddress(handle_, "VerifyCertificate");
			cfca_functions_.FreeMemory = (FreeMemoryPtr)UtilGetProcAddress(handle_, "FreeMemory");

			cfca_functions_.Initialize();

			bret = true;
		} while (false);
		
		return bret;
	}

	bool CFCA::Exit() {
		if(handle_) cfca_functions_.Uninitialize();
		//FreeLibrary(handle_);
		return true;
	}

	bool CFCA::GetSubjectDn(char* pszPFXFilePath, char* pszPFXPassword, char* pszInfoContent) {
		bool bret = false;
		do {
			int error_code = -1;
			char pszBase64CertContent[4096] = { 0 };
			if (!GetPublicCertContent("SM2", pszPFXFilePath, pszPFXPassword, pszBase64CertContent)) {
				break;
			}

			char* szInfoContent = NULL;
			if ((error_code = cfca_functions_.GetCertificateInfo(pszBase64CertContent, "SubjectDN", &szInfoContent)) != 0) {
				Error::PrintError(error_code);
				break;
			}

			strcpy(pszInfoContent, szInfoContent);

			cfca_functions_.FreeMemory(szInfoContent);

			bret = true;
		} while (false);

		return bret;
	}

	bool CFCA::GetSubjectDn(char* pszPublicFilePath, char* pszInfoContent) {
		bool bret = false;
		do {
			char pszBase64CertContent[4096] = { 0 };
			if (!ReadCertificateContent(pszPublicFilePath, pszBase64CertContent)) {
				break;
			}

			int error_code = 0;
			char* szInfoContent = NULL;
			if ((error_code = cfca_functions_.GetCertificateInfo(pszBase64CertContent, "SubjectDN", &szInfoContent)) != 0) {
				Error::PrintError(error_code);
				break;
			}

			strcpy(pszInfoContent, szInfoContent);
			cfca_functions_.FreeMemory(szInfoContent);

			bret = true;
		} while (false);

		return bret;
	}

	bool CFCA::GetAlgorithm(char* pszBase64CertContent, char* pszAlgorithm) {
		bool bret = false;
		do {
			int error_code = 0;
			char* szInfoContent = NULL;
			if ((error_code = cfca_functions_.GetCertificateInfo(pszBase64CertContent, "CertType", &szInfoContent)) != 0) {
				Error::PrintError(error_code);
				break;
			}

			strcpy(pszAlgorithm, szInfoContent);
			cfca_functions_.FreeMemory(szInfoContent);

			bret = true;
		} while (false);

		return bret;
	}

	bool CFCA::VerifyCertificate(char* pszPublicFilePath, int nCertVerifyFlag, char* pszTrustedCACertFilePath, char* pszCRLFilePath) {
		bool bret = false;
		do {
			char pszBase64CertContent[4096] = { 0 };
			if (!ReadCertificateContent(pszPublicFilePath, pszBase64CertContent)) {
				break;
			}

			int error_code = 0;
			if ((error_code = cfca_functions_.VerifyCertificate(pszBase64CertContent, 5, pszTrustedCACertFilePath, pszCRLFilePath)) != 0) {
				Error::PrintError(error_code);
				break;
			}

			bret = true;
		} while (false);

		return bret;
	}

	bool CFCA::ReadCertificateContent(char* pszCertFilePath, char* pszInfoContent) {
		bool bret = false;
		do {
			utils::File file;
			if (!file.Open(pszCertFilePath, utils::File::FILE_M_READ)) {
				LOG_ERROR("error: 打开文件(%s)失败\n", pszCertFilePath);
				break;
			}

			file.Read(pszInfoContent, 1, 4096);
			file.Close();

			bret = true;
		} while (false);

		return bret;
	}

	bool CFCA::GetPublicCertContent(char*  pszAlgorithm,char* pszPFXFilePath, char* pszPFXPassword, char* szBase64CertContent) {
		bool bret = false;
		do {
			char* pszBase64CertContent = NULL;
			int error_code = 0;
			if ((error_code = cfca_functions_.GetPublicCertFromPFX(pszAlgorithm, pszPFXFilePath, pszPFXPassword, &pszBase64CertContent)) != 0) {
				Error::PrintError(error_code);
				break;
			}
			strcpy(szBase64CertContent, pszBase64CertContent);

			cfca_functions_.FreeMemory(pszBase64CertContent);

			bret = true;
		} while (false);

		return bret;
	}

	bool CFCA::SignMessage(char* pszAlgorithm, char* pszPFXFilePath, char* pszPFXPassword, const char* pbySourceData, int nSourceSize, char* pszHashAlg, char* szBase64PKCS1Signature) {
		bool bret = false;
		do {
			char* pszBase64PKCS7DetachedSignature = NULL;
			int error_code = 0;
			if ((error_code = cfca_functions_.SignData_PKCS7Detached(pszAlgorithm, (unsigned char*)pbySourceData, nSourceSize, pszPFXFilePath, pszPFXPassword, pszHashAlg, &pszBase64PKCS7DetachedSignature)) != 0) {
				Error::PrintError(error_code);
				break;
			}
			strcpy(szBase64PKCS1Signature, pszBase64PKCS7DetachedSignature);

			cfca_functions_.FreeMemory(pszBase64PKCS7DetachedSignature);

			bret = true;
		} while (false);

		return bret;
	}

	bool CFCA::VerifySignature(char* pszAlgorithm, unsigned char* pbySourceData, int nSourceSize, char* pszBase64CertContent, char* pszHashAlg, char* pszBase64PKCS1Signature) {
		bool bret = false;
		do {
			int error_code = 0;
			if ((error_code = cfca_functions_.VerifyDataSignature_PKCS1(pszAlgorithm, (unsigned char*)pbySourceData, nSourceSize, pszBase64CertContent, pszHashAlg, pszBase64PKCS1Signature)) != 0) {
				Error::PrintError(error_code);
				break;
			}

			bret = true;
		} while (false);

		return bret;
	}

	bool CFCA::VerifySignature(char*  pszAlgorithm, unsigned char* pbySourceData, int nSourceSize, char* pszBase64PKCS7DetachedSignature, char** ppszP7DetachedBase64SignCertContent) {
		bool bret = false;
		do {
			int error_code = 0;
			if ((error_code = cfca_functions_.VerifyDataSignature_PKCS7Detached(pszAlgorithm, (unsigned char*)pbySourceData, nSourceSize, pszBase64PKCS7DetachedSignature, ppszP7DetachedBase64SignCertContent)) != 0) {
				Error::PrintError(error_code);
				break;
			}

			bret = true;
		} while (false);

		return bret;
	}

	bool CFCA::Verify(const std::string& msg, const std::string& sig, const std::string& publickey){
		if (!handle_){
			LOG_ERROR("cfca not support");
			return false;
		} 

		// check publickey is or not a base64 character string
		if (!IsBase64String(publickey)) {
			LOG_ERROR("public key is invalid, please check!");
			return false;
		}

		// check sign is or not a base64 character string
		if (!IsBase64String(sig)) {
			LOG_ERROR("sign data is invalid, please check!");
			return false;
		}

		char szAlgorithm[8] = { 0 };
		if (!GetAlgorithm((char*)publickey.c_str(), szAlgorithm)) {
			LOG_ERROR("GetAlgorithm failed");
			return false;
		}

		// p1 signature
		//if (!VerifySignature(szAlgorithm, (unsigned char*)msg.c_str(), nSourceSize, (char*)publickey.c_str(), 
		//	szAlgorithm == "RSA" ? "SHA-256" : "SM3", (char*)sig.c_str())) {
		//	printf("VerifySignature failed");
		//	return false;
		//}

		// p7 sign detach
		char* pszP7DetachedBase64SignCertContent = NULL;
		if (!VerifySignature(szAlgorithm, (unsigned char*)msg.c_str(), msg.size(), (char*)sig.c_str(), &pszP7DetachedBase64SignCertContent)) {
			LOG_ERROR("VerifySignature failed");
			return false;
		}

		cfca_functions_.FreeMemory(pszP7DetachedBase64SignCertContent);
		pszP7DetachedBase64SignCertContent = NULL;

		return true;
	}

	bool CFCA::IsBase64String(std::string msg) {
		// check publickey is or not a base64 character string
		if (msg.length() == 0 || msg.length() % 4 != 0) {
			return false;
		}

		int length = msg.find('=');
		if (length == -1) {
			length = msg.length();
		}
		for (int i = 0; i < length; i++) {
			char key = msg[i];
			if ((key >= 'a' && key <= 'z') || (key >= 'A' && key <= 'Z') || (key >= '0' && key <= '9') || key == '/' || key == '+') {
				continue;
			}
			else {
				return false;
			}
		}
		return true;
	}

	void Error::PrintError(int error_code) {
		switch (error_code) {
		case 0x80070057:
			LOG_ERROR("error: 0x%08x, parameter error", error_code);
			break;
		case 0x8007006E:
			LOG_ERROR("error: 0x%08x, Base64 encoding failed", error_code);
			break;
		case 0xA0071005:
			LOG_ERROR("error: 0x%08x, Base64 decoding failed", error_code);
			break;
		case 0xA0071031:
			LOG_ERROR("error: 0x%08x, invalid time for a certificate in the certificate chain", error_code);
			break;
		case 0xA0071032:
			LOG_ERROR("error: 0x%08x, the certificate has been revoked", error_code);
			break;
		case 0xA0071033:
			LOG_ERROR("error: 0x%08x, the certificate chain is incomplete", error_code);
			break;
		case 0xA0072021:
			LOG_ERROR("error: 0x%08x, invalid certificate use", error_code);
			break;
		case 0xA0071101:
			LOG_ERROR("error: 0x%08x, the data size exceeds the maximum limit", error_code);
			break;
		case 0xA0071102:
			LOG_ERROR("error: 0x%08x, recursive depth exceeds maximum limit", error_code);
			break;
		case 0xA0071103:
			LOG_ERROR("error: 0x%08x, SM2 file certificate parsing error", error_code);
			break;
		case 0xA0071104:
			LOG_ERROR("error: 0x%08x, invalid PKCS#7 signature format", error_code);
			break;
		case 0xA0071105:
			LOG_ERROR("error: 0x%08x, invalid digital envelope format", error_code);
			break;
		case 0xA0071106:
			LOG_ERROR("error: 0x%08x, the matching SM2 decryption certificate was not found", error_code);
			break;
		case 0xA0071107:
			LOG_ERROR("error: 0x%08x, signature failed", error_code);
			break;
		case 0xA0071108:
			LOG_ERROR("error: 0x%08x, failed to decrypt the SM2 file certificate", error_code);
			break;
		case 0xA0071109:
			LOG_ERROR("error: 0x%08x, failed to validate the certificate", error_code);
			break;
		case 0xA0071110:
			LOG_ERROR("error: 0x%08x, failed to obtain certificate information", error_code);
			break;
		case 0xFFFFFFFF:
			LOG_ERROR("error: 0x%08x, the operation failed (see the toolkit log file for specific reasons)", error_code);
			break;
		default:
			break;
		}
	}
}

