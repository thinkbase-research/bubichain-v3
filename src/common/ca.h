#pragma once

#include <stdio.h>
#include <map>
#include <openssl/safestack.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <memory.h>

// FORMAT_ASN1
#define DER                1
#define PEM                3   
#define P12                5   

namespace bubi {
	struct stuSUBJECT  {
		unsigned char C[4];			// country   
		unsigned char ST[4];		// province
		unsigned char L[12];		// locality
		unsigned char O[128];		// organization 
		unsigned char OU[128];		// organization unit
		unsigned char CN[128];		// common name  
		unsigned char MAIL[128];		// email
		unsigned char PMAIL[128];	// safe email
		unsigned char T[128];		// title
		unsigned char D[128];		// description   
		unsigned char G[128];		// given name
		unsigned char I[12];		// initial
		unsigned char NAME[128];		// name
		unsigned char S[128];		// surname
		unsigned char QUAL[12];		// qualifier
		unsigned char STN[12];		// pkcs9 unstructured name
		unsigned char PW[12];		// pkcs9 challenge password   
		unsigned char ADD[12];		// pkcs9 unstructured address
		char HD[33];				// hardware address
		char NI[50];				// node address
		stuSUBJECT() {
			memset(this, 0, sizeof(stuSUBJECT));
		}
	};

	struct stuKEYUSAGE { // key usage    
		bool DS; // Digital Signature   
		bool NR; // Non_Repudiation   
		bool KE; // Key_Encipherment   
		bool DE; // Data_Encipherment   
		bool KA; // keyAgreement   
		bool KC; // keyCertSign    
		bool CS; // cRLSign   
		bool EO; // Encipher Only   
		bool DO; // Decipher Only   
		stuKEYUSAGE() {
			memset(this, 0, sizeof(stuKEYUSAGE));
		}
	};

	struct stuEKEYUSAGE { // Enhanced key usage   
		bool SA;	// server authentication
		bool CA;	// client authentication
		bool CS;	// code sign
		bool EP;	// email protection
		bool TS;	// time stamping
		bool msCC;	// code complete
		bool msCTLS;// CTL Sign
		bool msSGC;	// online transaction processing
		bool msEFS;	// Encrypt data on disk
		bool msSC;	// Smart card login
		bool IP;	// Internet
		stuEKEYUSAGE() {
			memset(this, 0, sizeof(stuEKEYUSAGE));
		}
	};

	struct stuStatus {
		std::string hardware_address_;
		std::string node_id_;
	};

	typedef std::map<std::string, stuStatus> CAStatusMap;

	class CA {
	public:
		// make root certificate
		bool mkRoot(stuSUBJECT *rootInfo, X509 **x509p, RSA **rsa, EVP_PKEY **ppkey, int bits, int days, char *out_msg);

		// check root certificate
		bool CheckRootCert(const char *root_file_path, char *root_ext_code, int root_ext_len, char *out_msg);
		bool CheckRootCert(X509 *x509, char *root_ext_code, int root_ext_len, char *out_msg);

		// get root code
		bool GetRootCode(const char *root_file_path, char* root_ext_code, int root_ext_len, char *out_msg);
		bool GetRootCode(X509 *x509, char* root_ext_code, int root_ext_len, char *out_msg);

		// make certificate
		bool MakeCert(const char *certfile, const char *keyfile, const char *password, char *enddate, int days, 
			const char *reqfile, stuKEYUSAGE *KUSAGE, stuEKEYUSAGE *EKUSAGE, const char *outfile, bool ca_enable,
			char *serial, char *common_name, int cn_len, char *organization, int o_len, char *email, int mail_len, char *out_msg, int type = PEM);

		// check certificate
		bool CheckEntityCert(const char *issuer_cert_file, const char *subject_cert_file, const char *key_file, const char *password, char *out_msg);

		// make request certificate
		bool MakeReq(stuSUBJECT *reqinfo, int bits, const char *req_file, const char *pri_file, const char *password, char *out_msg, int type = PEM);

		// get cert serial
		bool GetCertSerial(const char *certfile, char *serial, char *out_msg);
		bool GetCertSerial(X509 *x509, char *serial, char *out_msg);

		// get request certificate info
		bool GetReqContent(const char *reqfile, stuSUBJECT& reqInfo, char *out_msg);

		// get the hardware address and node id in the certificate
		bool GetHDAndDA(const char *file_path, char *hardware_address, int hard_len, char *node_id, int id_len, char *out_msg);
		bool GetHDAndDA(X509 *x509, char *hardware_address, int hard_len, char *node_id, int id_len, char *out_msg);
		bool GetHDAndDA(X509_REQ *x509_req, char *hardware_address, int hard_len, char *node_id, int id_len, char *out_msg);

		// get ca certificate enable
		bool GetCAEnabled(const char *cert_file, bool& cert_enabled, char *out_msg);

		// check certificate validity
		bool CheckCertValidity(X509 *x509, char *not_before, char *not_after, char *out_msg);

	private:

		// make root code
		bool mkRootCode(stuSUBJECT *rootInfo, char *not_before, char *not_after, std::string& root_code);

		// get the hardware address and node id in the certificate
		bool GetReqHDAndDA(const char *reqfile, char *hardware_address, int hard_len, char *node_id, int id_len,  char *out_msg);

		bool GetCertHDAndDA(const char *cert_path, char *hardware_address, int hard_len, char *node_id, int id_len, char *out_msg);

		// get extension data in the certificate
		bool GetExtensionData(X509 *x509, const char *oid, const char *sn, const char *ln, char *data, unsigned int len, char *out_msg);

		// certify certificate
		bool certify(X509 **xret, X509_REQ *req, EVP_PKEY *pkey, X509 *x509, const EVP_MD *dgst, const char *startdate, 
			const char *enddate, int days, stuKEYUSAGE *KUSAGE, stuEKEYUSAGE *EKUSAGE, bool ca_enable, char *serial, char *common_name,
			int cn_len, char *organization, int o_len, char *email, int mail_len, char *out_msg);

		// make body of the certificate
		bool do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509, const EVP_MD *dgst, const char *startdate, 
			const char *enddate, int days, X509_REQ *req, stuKEYUSAGE *KUSAGE, stuEKEYUSAGE *EKUSAGE, bool ca_enable,
			char *serial, char *common_name, int cn_len, char *organization, int o_len, char *email, int mail_len, char *out_msg);

		// copy extensions from request certificate
		bool copy_extensions(X509 *x, X509_REQ *req, int copy_type);

		// make request certificate
		bool mkReq(stuSUBJECT *reqInfo, X509_REQ **req, RSA **rsa, EVP_PKEY **pkeyp, int bits, char *out);

		// add extension in request certificate
		bool Add_ExtReq(STACK_OF(X509_EXTENSION) *sk, int nid, char *value);

		// add subject name
		bool Add_Name(X509_NAME *x509name, int type, char *iput, int ilen, char *outMsg);

		// add extension to user certificate
		int Add_ExtCert(X509 *cert, X509 *root, int nid, const char *value);

		// make random
		bool Rand(const char *file, int dont_warn, char *out_msg);

		// load key from private certificate file
		EVP_PKEY *LoadKey(const char *key, int keylen, const char *pass, char *out_msg);
		EVP_PKEY *load_key(BIO *bio, int format, const char *pass, char *out_msg);

		// load cert from certificate file
		X509 *LoadCert(const char *cert, int certlen, char *outMsg);
		X509 *load_cert(BIO *cert, int format, char *pwd, char *outMsg);

		// generate a random serial number
		bool rand_serial(char *serial, BIGNUM *b, ASN1_INTEGER *ai);

	private:
		// ASN1_Time format change
		int asn1_time_to_tm(struct tm *tm, const ASN1_TIME *t);
		int asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d);
		int asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d);
		int OPENSSL_gmtime_adj(struct tm *tm, int off_day, long offset_sec);
		void julian_to_date(long jd, int *y, int *m, int *d);
		int julian_adj(const struct tm *tm, int off_day, long offset_sec, long *pday, int *psec);
		long date_to_julian(int y, int m, int d);
		struct tm *OPENSSL_gmtime(const time_t *timer, struct tm *result);
	};
}