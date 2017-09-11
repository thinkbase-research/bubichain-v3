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

#ifndef CFCA_H_
#define CFCA_H_

#include <string>
#include <utils/singleton.h>

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#define HMODULE void*
#define WINAPI
#endif

namespace cfca {

	class Error {
	public:
		static void PrintError(int error_code);
	};

	class CFCA : public utils::Singleton<CFCA> {
		typedef int  (WINAPI *InitializePtr)();
		typedef int  (WINAPI *UninitializePtr)();
		typedef int  (WINAPI *SignData_PKCS1Ptr)(char*, unsigned char*, int, char*, char*, char*, char**);
		typedef int  (WINAPI *SignData_PKCS7DetachedPtr)(char*, unsigned char*, int, char*, char*, char*, char**);
		typedef int  (WINAPI *SignData_PKCS7AttachedPtr)(char*, unsigned char*, int, char*, char*, char*, char**);
		typedef int  (WINAPI *SignFile_PKCS7DetachedPtr)(char*, char*, char*, char*, char*, char**);
		typedef int  (WINAPI *VerifyDataSignature_PKCS1Ptr)(char*, unsigned char*, int, char*, char*, char*);
		typedef int  (WINAPI *VerifyDataSignature_PKCS7DetachedPtr)(char*, unsigned char*, int, char*, char**);
		typedef int  (WINAPI *VerifyDataSignature_PKCS7AttachedPtr)(char*, char*, char**, unsigned char**, int*);
		typedef int  (WINAPI *VerifyFileSignature_PKCS7DetachedPtr)(char*, char*, char*, char**);
		typedef int  (WINAPI *EncryptDataToCMSEnvelopePtr)(char*, unsigned char*, int, char*, char*, char**);
		typedef int  (WINAPI *SignAndEncryptDataPtr)(char*, unsigned char*, int, char*, char*, char*, char*, char*, char**);
		typedef int  (WINAPI *DecryptDataFromCMSEnvelopePtr)(char*, char*, char*, char*, unsigned char**, int*);
		typedef int  (WINAPI *DecryptAndVerifyDataSignaturePtr)(char*, char*, char*, char*, unsigned char**, int*);
		typedef int  (WINAPI *VerifyCertificatePtr)(char*, int, char*, char*);
		typedef int  (WINAPI *GetCertificateInfoPtr)(char*, char*, char**);
		typedef int  (WINAPI *GetPublicCertFromPFXPtr) (char*, char*, char*, char**);
		typedef void (WINAPI *FreeMemoryPtr)(void*);

		struct CFCA_FUNCTION {
			InitializePtr                        Initialize;
			UninitializePtr                      Uninitialize;
			SignData_PKCS1Ptr                    SignData_PKCS1;
			SignData_PKCS7DetachedPtr            SignData_PKCS7Detached;
			SignData_PKCS7AttachedPtr            SignData_PKCS7Attached;
			SignFile_PKCS7DetachedPtr            SignFile_PKCS7Detached;
			VerifyDataSignature_PKCS1Ptr         VerifyDataSignature_PKCS1;
			VerifyDataSignature_PKCS7DetachedPtr VerifyDataSignature_PKCS7Detached;
			VerifyDataSignature_PKCS7AttachedPtr VerifyDataSignature_PKCS7Attached;
			VerifyFileSignature_PKCS7DetachedPtr VerifyFileSignature_PKCS7Detached;
			EncryptDataToCMSEnvelopePtr          EncryptDataToCMSEnvelope;
			SignAndEncryptDataPtr                SignAndEncryptData;
			DecryptDataFromCMSEnvelopePtr        DecryptDataFromCMSEnvelope;
			DecryptAndVerifyDataSignaturePtr     DecryptAndVerifyDataSignature;
			VerifyCertificatePtr                 VerifyCertificate;
			GetCertificateInfoPtr                GetCertificateInfo;
			FreeMemoryPtr                        FreeMemory;
			GetPublicCertFromPFXPtr              GetPublicCertFromPFX;
		};

		bool GetPublicCertContent(char*  pszAlgorithm, char* pszPFXFilePath, char* pszPFXPassword, char* pszBase64CertContent);
		bool ReadCertificateContent(char* pszCertFilePath, char* pszInfoContent);
		bool GetSubjectDn(char* pszPFXFilePath, char* pszPFXPassword, char* pszInfoContent);
		bool GetSubjectDn(char* pszPublicFilePath, char* pszInfoContent);
		//bool GetAlgorithm(char* pszBase64CertContent, char* pszAlgorithm);
		bool VerifyCertificate(char* pszPublicFilePath, int nCertVerifyFlag, char* pszTrustedCACertFilePath, char* pszCRLFilePath);
		bool SignMessage(char* pszAlgorithm, char* pszPFXFilePath, char* pszPFXPassword, const char* pbySourceData, int nSourceSize, char* pszHashAlg, char* pszBase64PKCS1Signature);
		bool VerifySignature(char*  pszAlgorithm, unsigned char* pbySourceData, int nSourceSize, char* pszBase64CertContent, char* pszHashAlg, char* pszBase64PKCS1Signature);
		bool VerifySignature(char*  pszAlgorithm, unsigned char* pbySourceData, int nSourceSize, char* pszBase64PKCS7DetachedSignature, char** ppszP7DetachedBase64SignCertContent);
		bool IsBase64String(std::string msg);

	public:
		bool Initialize();
		bool GetAlgorithm(char* pszBase64CertContent, char* pszAlgorithm);
		bool Verify(const std::string& msg, const std::string& sig, const std::string& pubcontent);
		bool Exit();

	private:
		CFCA_FUNCTION cfca_functions_;
		HMODULE handle_;
	};
}

#endif
