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

#include "ca.h"
#include "strings.h"
#include "file.h"
#include "crypto.h"
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/engine.h>
#include <locale.h>
#include <exception>

#define SECS_PER_DAY (24 * 60 * 60)
#define EXT_COPY_NONE   0
#define EXT_COPY_ADD    1
#define EXT_COPY_ALL    2

namespace utils {

bool CA::mkRootCode(stuSUBJECT *rootInfo, char *not_before, char *not_after, std::string& root_code) {
	bool bret = false;
	do {
		const std::string code_one = "0BAED4FBA6604DFE875D95761A137199757D7369CAF44E67B1BF8C4DE86BE288";
		const std::string code_two = "E1F58B5221B346578C415876384F596F83FC186580F2443F9E33A0B63AB7FB2F";
		std::string src = code_one + (char*)rootInfo->CN + (char*)rootInfo->MAIL + code_two + (char*)rootInfo->OU + not_before + not_after;
		root_code = utils::String::BinToHexString(utils::Sha256::Crypto(src));
		bret = true;
	} while (false);
	return bret;
}

X509 *CA::load_cert(BIO *cert, int format, char *pwd, char *out_msg) {
	X509 *x = NULL;
	bool format_valid = true;
	switch (format)
	{
	case DER:
		x = d2i_X509_bio(cert, NULL);
		break;
	case PEM:
		x = PEM_read_bio_X509(cert, NULL, NULL, NULL);
		break;
	case P12:
		{
			PKCS12 *p12 = d2i_PKCS12_bio(cert, NULL);
			PKCS12_parse(p12, pwd, NULL, &x, NULL);
			PKCS12_free(p12);
			p12 = NULL;
		}
		break;
	default:
		format_valid = false;
		strcpy(out_msg, "bad input format specified for input cert");
		break;
	}
	if (x == NULL && format_valid) {
		strcpy(out_msg, "unable to load certificate");
	}
	return x;
}

X509 *CA::LoadCert(const char *cert, int certlen, char *out_msg) {
	BIO *in = NULL;
	X509 *x509 = NULL;
	if (certlen == 0) {
		if ((in = BIO_new_file(cert, "r")) == NULL) {
			sprintf(out_msg, "open CA certificate file(%s) failed", cert);
			return NULL;
		}
	}
	else {
		if ((in = BIO_new_mem_buf((void*)cert, certlen)) == NULL) {
			strcpy(out_msg, "make Memory BIO Error");
			return NULL;
		}
	}
	if ((x509 = load_cert(in, DER, NULL, out_msg)) == NULL)
	{
		BIO_reset(in);
		memset(out_msg, 0, strlen(out_msg));
		x509 = load_cert(in, PEM, NULL, out_msg);  
	}
	if (in != NULL) BIO_free(in);
	return x509;
}

EVP_PKEY *CA::load_key(BIO *bio, int format, const char *pass, char *out_msg) {
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	bool format_valid = true;
	switch (format) {
	case DER:
		rsa = d2i_RSAPrivateKey_bio(bio, NULL);
		break;
	case PEM:
		rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, (void*)pass);
		break;
	case P12:
		{
			PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
			PKCS12_parse(p12, pass, &pkey, NULL, NULL);
			PKCS12_free(p12);
			p12 = NULL;
		}
		break;
	default:
		format_valid = false;
		sprintf(out_msg, "bad input format specified for key");
		break;
	}

	if (rsa) {
		pkey = EVP_PKEY_new();
		if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
			strcpy(out_msg, "EVP_PKEY_assign_RSA failed");
		}
	}
	if (NULL == pkey && format_valid) {
		sprintf(out_msg, "password of Private Key is invalid");
	}
	return pkey;
}

EVP_PKEY *CA::LoadKey(const char *key, int keylen, const char *pass, char *out_msg) {
	EVP_PKEY *pkey = NULL;
	BIO *in = NULL;
	do {
		OpenSSL_add_all_algorithms();
		if (keylen == 0) {// in file
			if ((in = BIO_new_file(key, "r")) == NULL) {
				sprintf(out_msg, "open CA certificate file(%s) failed", key);
				break;
			}
		}
		else { // in memory
			if ((in = BIO_new_mem_buf((void*)key, keylen)) == NULL) {
				strcpy(out_msg, "make member bio error");
				break;
			}
		}
		if ((pkey = load_key(in, DER, pass, out_msg)) == NULL) {
			// BIO can read and write, so the data in BIO must be clearned; 
			// or BIO only can read, this operation only set the point to head
			BIO_reset(in);
			memset(out_msg, 0, strlen(out_msg));
			pkey = load_key(in, PEM, pass, out_msg);
		}
	} while (false);
	if (in != NULL) BIO_free(in);
	return pkey;
}

bool CA::rand_serial(char *serial, BIGNUM *b, ASN1_INTEGER *ai) {
	bool bret = false;
	BIGNUM *btmp = NULL;
	do {
		if (NULL == serial) break;

		const int SERIAL_RAND_BITS = 128;
		if (b) btmp = b;
		else btmp = BN_new();

		if (!btmp) break;

		if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
			break;
		if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
			break;

		strcpy(serial, BN_bn2hex(btmp));
		bret = true;
	} while (false);

	if (!b) BN_free(btmp);
	return bret;
}

bool CA::Rand(const char *file, int dont_warn, char *out_msg) {
	bool bret = false;
	do {
		int consider_randfile = (file == NULL);
		char buffer[200];
#ifdef OPENSSL_SYS_WINDOWS
		RAND_screen();
#endif
		if (file == NULL)
			file = RAND_file_name(buffer, sizeof buffer);
		else if (RAND_egd(file) > 0) {
			bret = true;
			break;
		}
		if (file == NULL || !RAND_load_file(file, -1)) {
			if (RAND_status() == 0 && !dont_warn)
			{
				sprintf(out_msg, "unable to load 'random state'");
				sprintf(out_msg, ", This means that the random number generator has not been seeded");
				if (consider_randfile) /* explanation does not apply when a file is explicitly named */
				{
					sprintf(out_msg, "Consider setting the RANDFILE environment variable to point at a file that");
					sprintf(out_msg, ", 'random' data can be kept in (the file will be overwritten).");
				}
			}
			break;
		}
		bret = true;
	} while (false);
	return bret;
}

int CA::Add_ExtCert(X509 *cert, X509 *root , int nid, const char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);      
	X509V3_set_ctx(&ctx, root, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
	if (!ex) return 0;
	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}

bool CA::Add_Name(X509_NAME *x509name, int type, char *iput, int ilen, char *out_msg) {
	bool bret = false;
	do {
		int wslen, wcnt, i;
		char input[256] = { 0 };
		strncpy(input, iput, ilen);
		wslen = strlen(input) + 1;
		if (wslen == 1) {
			bret = true;
			break;
		}

		wchar_t *ws, wc;
		ws = new wchar_t[sizeof(wchar_t) *wslen];
		if ((wcnt = mbstowcs(ws, input, wslen)) == -1) {
			if (ws) delete[] ws;
			break;
		}
		ASN1_STRING stmp, *str = &stmp;
		unsigned char cbuf[256] = { 0 };
		for (i = 0; i < (int)wcslen(ws); i++)
		{
			wc = ws[i];
			cbuf[2 *i] = wc / 256;
			cbuf[2 *i + 1] = wc % 256;
		}

		// must initialize
		stmp.data = NULL;
		stmp.length = 0;
		stmp.flags = 0;
		ASN1_mbstring_copy(&str, cbuf, 2 *wslen, MBSTRING_BMP, B_ASN1_UTF8STRING);
		X509_NAME_add_entry_by_NID(x509name, type, V_ASN1_UTF8STRING, stmp.data, -1, -1, 0);
		if (ws) delete[] ws;
		bret = true;
	} while (false);
	return bret;
}

bool CA::Add_ExtReq(STACK_OF(X509_EXTENSION) *sk, int nid, char *value) {
	bool bret = true;
	do {
		X509_EXTENSION *ex;
		ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
		if (!ex) break;
		sk_X509_EXTENSION_push(sk, ex);
		bret = true;
	} while (false);
	return bret;
}

bool CA::mkReq(stuSUBJECT *reqInfo, X509_REQ **req, RSA **rsa, EVP_PKEY **pkeyp, int bits, char *out) {
	bool bret = false;
	do {
		X509_REQ *x;
		EVP_PKEY *pk;
		X509_NAME *name = NULL;
		ASN1_STRING stmp, *str = &stmp;
		STACK_OF(X509_EXTENSION) *exts = NULL;
		if ((pk = EVP_PKEY_new()) == NULL) {
			strcpy(out, "new EVP_PKEY failed");
			break;
		}
		if ((x = X509_REQ_new()) == NULL) {
			strcpy(out, "new X509_REQ failed");
			break;
		}
		Rand(NULL, 1, out);
		*rsa = RSA_generate_key(bits, RSA_3, 0, NULL);
		if (!EVP_PKEY_assign_RSA(pk, *rsa)) {
			strcpy(out, "EVP_PKEY_assign_RSA failed");
			break;
		}
		X509_REQ_set_pubkey(x, pk);
		name = X509_REQ_get_subject_name(x);
		setlocale(LC_CTYPE, "");
		Add_Name(name, NID_countryName, (char *)reqInfo->C, sizeof(reqInfo->C), out);
		Add_Name(name, NID_stateOrProvinceName, (char *)reqInfo->ST, sizeof(reqInfo->ST), out);
		Add_Name(name, NID_localityName, (char *)reqInfo->L, sizeof(reqInfo->L), out);
		Add_Name(name, NID_organizationName, (char *)reqInfo->O, sizeof(reqInfo->O), out);
		Add_Name(name, NID_organizationalUnitName, (char *)reqInfo->OU, sizeof(reqInfo->OU), out);
		Add_Name(name, NID_commonName, (char *)reqInfo->CN, sizeof(reqInfo->CN), out);
		Add_Name(name, NID_pkcs9_emailAddress, (char *)reqInfo->MAIL, sizeof(reqInfo->MAIL), out);
		Add_Name(name, NID_email_protect, (char *)reqInfo->PMAIL, sizeof(reqInfo->PMAIL), out);
		Add_Name(name, NID_title, (char *)reqInfo->T, sizeof(reqInfo->T), out);
		Add_Name(name, NID_description, (char *)reqInfo->D, sizeof(reqInfo->D), out);
		Add_Name(name, NID_givenName, (char *)reqInfo->G, sizeof(reqInfo->G), out);
		Add_Name(name, NID_initials, (char *)reqInfo->I, sizeof(reqInfo->I), out);
		Add_Name(name, NID_name, (char *)reqInfo->NAME, sizeof(reqInfo->NAME), out);
		Add_Name(name, NID_surname, (char *)reqInfo->S, sizeof(reqInfo->S), out);
		Add_Name(name, NID_dnQualifier, (char *)reqInfo->QUAL, sizeof(reqInfo->QUAL), out);
		Add_Name(name, NID_pkcs9_unstructuredName, (char *)reqInfo->STN, sizeof(reqInfo->STN), out);
		Add_Name(name, NID_pkcs9_challengePassword, (char *)reqInfo->PW, sizeof(reqInfo->PW), out);
		Add_Name(name, NID_pkcs9_unstructuredAddress, (char *)reqInfo->ADD, sizeof(reqInfo->ADD), out);

		// add self extensions
		exts = sk_X509_EXTENSION_new_null();
		int nid;
		// node_address
		nid = OBJ_create("1.1.1.1", "node_id", "Node Id");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		Add_ExtReq(exts, nid, reqInfo->NI);
		// hard_address
		nid = OBJ_create("1.1.1.2", "hard_address", "Hared Address");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		Add_ExtReq(exts, nid, reqInfo->HD);
		// Now we've created the extensions we add them to the request
		X509_REQ_add_extensions(x, exts);
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		// cleanup the extension code if any custom extensions have been added
		X509V3_EXT_cleanup();
		// add sign algorithm in request certificate
		if (!X509_REQ_sign(x, pk, EVP_sha256())) {
			strcpy(out, "X509_REQ_sign failed");
			break;
		}
		*req = x;
		*pkeyp = pk;
		bret = true;
	} while (false);
	return bret;
}

bool CA::MakeReq(stuSUBJECT *reqinfo, int bits, const char *req_file, const char *pri_file, 
	const char *password, char *out_msg, int type) {
	bool bret = false;
	X509_REQ *req = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	BIO *breq = NULL, *bkey = NULL;
	do {
		int i = 0, j = 0;
		// add signature algorithm
		OpenSSL_add_all_digests();
		if (((breq = BIO_new_file(req_file, "w+")) == NULL) || ((bkey = BIO_new_file(pri_file, "w+")) == NULL)) {
			strcpy(out_msg, "Create File Error");
			break;
		}

		if (!mkReq(reqinfo, &req, &rsa, &pkey, bits, out_msg)) {
			break;
		}
		if (type == PEM) {
			i = PEM_write_bio_X509_REQ(breq, req);
			j = PEM_write_bio_RSAPrivateKey(bkey, rsa, EVP_des_ede3_cbc(), NULL, 0, NULL, (char *)password);
		}
		else if (type == DER) {
			i = i2d_X509_REQ_bio(breq, req);
			j = i2d_PrivateKey_bio(bkey, pkey);
		}

		if (!i || !j) {
			strcpy(out_msg, "Save Cert or Key File Error");
			break;
		}
		bret = true;
	} while (false);

	if (breq) BIO_free(breq);
	if (bkey) BIO_free(bkey);
	if (req) X509_REQ_free(req);
	if (pkey) EVP_PKEY_free(pkey);

	if (false == bret) {
		if (utils::File::IsExist(req_file)) {
			utils::File::Delete(req_file);
		}
		if (utils::File::IsExist(pri_file)) {
			utils::File::Delete(pri_file);
		}

	}
	return bret;
}

bool CA::copy_extensions(X509 *x, X509_REQ *req, int copy_type) {
	bool bret = false;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	do {
		X509_EXTENSION *ext, *tmpext;
		ASN1_OBJECT *obj;
		int i, idx, ret = 0;
		if (!x || !req || (copy_type == EXT_COPY_NONE)) {
			bret = true;
			break;
		}
		exts = X509_REQ_get_extensions(req);
		for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
			ext = sk_X509_EXTENSION_value(exts, i);
			obj = X509_EXTENSION_get_object(ext);
			idx = X509_get_ext_by_OBJ(x, obj, -1);
			// does extension exist
			if (idx != -1) {
				// if normal copy don't override existing extension
				if (copy_type == EXT_COPY_ADD)
					continue;
				do { // delete all extensions of same type
					tmpext = X509_get_ext(x, idx);
					X509_delete_ext(x, idx);
					X509_EXTENSION_free(tmpext);
					idx = X509_get_ext_by_OBJ(x, obj, -1);
				} while (idx != -1);
			}
			if (!X509_add_ext(x, ext, -1)) {
				break;
			}
		}
		bret = true;
	} while (false);
	if (exts) sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return bret;
}

bool CA::do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509, const EVP_MD *dgst, const char *startdate, 
	const char *enddate, int days, X509_REQ *req, stuKEYUSAGE *KUSAGE, stuEKEYUSAGE *EKUSAGE, bool ca_enable,
	char *serial, char *common_name, int cn_len, char *organization, int o_len, char *email, int mail_len, char *out_msg) {
	bool bret = false;
	X509_NAME *name = NULL, *CAname = NULL;
	X509 *ret = NULL;
	do {
		//X509_CINF *ci;
		EVP_PKEY *pktmp;
		int i = 0;
		char kusage[160] = { 0 };
		char ekusage[360] = { 0 };
		name = X509_REQ_get_subject_name(req);
		if ((ret = X509_new()) == NULL) {
			strcpy(out_msg, "X509_new failed");
			break;
		}
		//ci = ret->cert_info;

		if (!X509_set_version(ret, 2L)) { // version
			strcpy(out_msg, "X509_set_version failed");
			break;
		}
		if (!rand_serial(serial, NULL, X509_get_serialNumber(ret))) { // serial number
			strcpy(out_msg, "rand_serial failed");
			break;
		}
		if (!X509_set_issuer_name(ret, X509_get_subject_name(x509))) { // subject name
			strcpy(out_msg, "X509_set_issuer_name failed");
			break;
		}
		if (strcmp(startdate, "today") == 0)
			X509_gmtime_adj(X509_get_notBefore(ret), 0);
		else ASN1_UTCTIME_set_string(X509_get_notBefore(ret), startdate); // begin time

		if (enddate == NULL)
			X509_gmtime_adj(X509_get_notAfter(ret), (long)60 *60 *24 *days);
		else ASN1_UTCTIME_set_string(X509_get_notAfter(ret), enddate); // end time

		if (!X509_set_subject_name(ret, name)) {
			strcpy(out_msg, "X509_set_subject_name failed");
			break;
		}
		pktmp = X509_REQ_get_pubkey(req);
		i = X509_set_pubkey(ret, pktmp);
		EVP_PKEY_free(pktmp);
		if (!i) {
			strcpy(out_msg, "X509_set_pubkey failed");
			break;
		}
		// add request extensions
		if (!copy_extensions(ret, req, EXT_COPY_ALL)) {
			strcpy(out_msg, "add these extensions in request certificate failed");
			break;
		}
		// add default extensions
		Add_ExtCert(ret, ret, NID_basic_constraints, "critical,CA:FALSE");
		Add_ExtCert(ret, ret, NID_subject_key_identifier, "hash");
		Add_ExtCert(ret, x509, NID_authority_key_identifier, "keyid,issuer:always");

		// set the keyUsage
		if (KUSAGE->DS) strcpy(kusage, "digitalSignature");
		if (KUSAGE->NR) {
			if (strlen(kusage)) strcat(kusage, ",nonRepudiation");
			else strcpy(kusage, "nonRepudiation");
		}
		if (KUSAGE->KE) {
			if (strlen(kusage)) strcat(kusage, ",keyEncipherment");
			else strcpy(kusage, "keyEncipherment");
		}
		if (KUSAGE->DE) {
			if (strlen(kusage)) strcat(kusage, ",dataEncipherment");
			else strcpy(kusage, "dataEncipherment");
		}
		if (KUSAGE->KA) {
			if (strlen(kusage)) strcat(kusage, ",keyAgreement");
			else strcpy(kusage, "keyAgreement");
		}
		if (KUSAGE->KC) {
			if (strlen(kusage)) strcat(kusage, ",keyCertSign");
			else strcpy(kusage, "keyCertSign");
		}
		if (KUSAGE->CS) {
			if (strlen(kusage)) strcat(kusage, ",cRLSign");
			else strcpy(kusage, "cRLSign");
		}
		if (KUSAGE->EO) {
			if (strlen(kusage)) strcat(kusage, ",encipherOnly");
			else strcpy(kusage, "encipherOnly");
		}
		if (KUSAGE->DO) {
			if (strlen(kusage)) strcat(kusage, ",decipherOnly");
			else strcpy(kusage, "decipherOnly");
		}
		if (strlen(kusage))
			Add_ExtCert(ret, ret, NID_key_usage, kusage);
		if (EKUSAGE->SA) strcpy(ekusage, "serverAuth");
		if (EKUSAGE->CA) {
			if (strlen(ekusage)) strcat(ekusage, ",clientAuth");
			else strcpy(ekusage, "clientAuth");
		}
		if (EKUSAGE->CS) {
			if (strlen(ekusage)) strcat(ekusage, ",codeSigning");
			else strcpy(ekusage, "codeSigning");
		}
		if (EKUSAGE->EP) {
			if (strlen(ekusage)) strcat(ekusage, ",emailProtection");
			else strcpy(ekusage, "emailProtection");
		}
		if (EKUSAGE->TS) {
			if (strlen(ekusage)) strcat(ekusage, ",timeStamping");
			else strcpy(ekusage, "timeStamping");
		}
		if (EKUSAGE->msCC) {
			if (strlen(ekusage)) strcat(ekusage, ",msCodeCom");
			else strcpy(ekusage, "msCodeCom");
		}
		if (EKUSAGE->msCTLS) {
			if (strlen(ekusage)) strcat(ekusage, ",msCTLSign");
			else strcpy(ekusage, "msCTLSign");
		}
		if (EKUSAGE->msSGC) {
			if (strlen(ekusage)) strcat(ekusage, ",msSGC");
			else strcpy(ekusage, "msSGC");
		}
		if (EKUSAGE->msEFS) {
			if (strlen(ekusage)) strcat(ekusage, ",msEFS");
			else strcpy(ekusage, "msEFS");
		}
		if (EKUSAGE->msSC) {
			if (strlen(ekusage)) strcat(ekusage, ",msSmartcardLogin");
			else strcpy(ekusage, "msSmartcardLogin");
		}
		if (EKUSAGE->IP) {
			if (strlen(ekusage)) strcat(ekusage, ",ipsecEndSystem,ipsecTunnel,ipsecUser");
			else strcpy(ekusage, "ipsecEndSystem,ipsecTunnel,ipsecUser");
		}
		if (strlen(ekusage))
			Add_ExtCert(ret, ret, NID_ext_key_usage, ekusage);

		int nid = OBJ_create("1.1.1.3", "use_ca", "Use CA");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		if (ca_enable) Add_ExtCert(ret, ret, nid, "true");
		else Add_ExtCert(ret, ret, nid, "false");
		//cleanup the extension code if any custom extensions have been added
		X509V3_EXT_cleanup();
		// add signature algorithm  
		if (!X509_sign(ret, pkey, dgst)) {
			strcpy(out_msg, "X509_sign failex");
			break;
		}

		X509_NAME_get_text_by_NID(name, NID_organizationName, organization, o_len);
		X509_NAME_get_text_by_NID(name, NID_commonName, common_name, cn_len);
		X509_NAME_get_text_by_NID(name, NID_pkcs9_emailAddress, email, mail_len);

		bret = true;
	} while (false);
	if (CAname != NULL)
		X509_NAME_free(CAname);
	if (!bret) {
		if (ret != NULL) X509_free(ret);
		ret = NULL;
	}
	else
		*xret = ret;
	return bret;
}

bool CA::certify(X509 **xret, X509_REQ *req, EVP_PKEY *pkey, X509 *x509, const EVP_MD *dgst, 
	const char *startdate, const char *enddate, int days, stuKEYUSAGE *KUSAGE, stuEKEYUSAGE *EKUSAGE, bool ca_enable,
	char *serial, char *common_name, int cn_len, char *organization, int o_len, char *email, int mail_len, char *out_msg) {
	bool bret = false;
	do {
		EVP_PKEY *pktmp = NULL;
		int ok = -1, i = 0;
		if ((pktmp = X509_REQ_get_pubkey(req)) == NULL) {
			strcpy(out_msg, "error unpacking public key");
			break;
		}
		// check signature  
		i = X509_REQ_verify(req, pktmp);  
		EVP_PKEY_free(pktmp);
		if (i < 0) {
			strcpy(out_msg, "Signature verification problems.");
			break;
		}
		if (i == 0) {
			strcpy(out_msg, "Signature did not match the certificate request");
			break;
		}
		bret = do_body(xret, pkey, x509, dgst, startdate, enddate, days, req, KUSAGE, EKUSAGE, ca_enable,
			serial, common_name, cn_len, organization, o_len, email, mail_len, out_msg);
	} while (false);
	return bret;
}

bool CA::GetRootCode(const char *root_file_path, char* root_ext_code, int root_ext_len, char *out_msg) {
	bool bret = false;
	X509 *x509 = NULL;
	do {
		x509 = LoadCert(root_file_path, 0, out_msg);
		if (x509 == NULL) {
			break;
		}
		bret = GetRootCode(x509, root_ext_code, root_ext_len, out_msg);
	} while (false);

	if (x509) X509_free(x509);
	return bret;
}

bool CA::GetRootCode(X509 *x509, char* root_ext_code, int root_ext_len, char *out_msg) {
	bool bret = false;
	do  {
		if (NULL == root_ext_code) {
			sprintf(out_msg, "root ext buffer is emtpy");
			break;
		}
		if (!GetExtensionData(x509, "1.12.30663.195.6325", "root_code", "Root Code", root_ext_code, root_ext_len, out_msg)) {
			break;
		}
		bret = true;
	} while (false);
	return bret;
}

bool CA::MakeCert(const char *certfile, const char *keyfile, const char *password, char *enddate, int days,
	const char *reqfile, stuKEYUSAGE *KUSAGE, stuEKEYUSAGE *EKUSAGE, const char *outfile, bool ca_enable,
	char *serial, char *common_name, int cn_len, char *organization, int o_len, char *email, int mail_len, char *out_msg, int type) {
	bool bret = false;
	X509_REQ *req = NULL;
	EVP_PKEY *prkey = NULL;// root private key
	X509 *x509 = NULL, *x = NULL;// root ca, user ca
	BIO *reqbio = NULL, *bcert = NULL; // generate file
	do {
		const EVP_MD *dgst = NULL;
		int j = 0, ok = 0;
		OpenSSL_add_all_digests();// add signature algorithm
		if ((reqbio = BIO_new_file(reqfile, "r")) == NULL || (bcert = BIO_new_file(outfile, "w+")) == NULL) {
			sprintf(out_msg, "open file(%s) failed", (NULL == reqbio ? reqfile : outfile));
			break;
		}
		BIO_set_close(bcert, BIO_CLOSE);
		BIO_set_close(reqbio, BIO_CLOSE);

		if ((req = PEM_read_bio_X509_REQ(reqbio, NULL, NULL, NULL)) == NULL) {
			BIO_reset(reqbio);
			if ((req = d2i_X509_REQ_bio(reqbio, NULL)) == NULL) {
				sprintf(out_msg, "error get certificate request");
				break;
			}
		}
		prkey = LoadKey(keyfile, 0, password, out_msg);
		if (prkey == NULL) {
			sprintf(out_msg, "loadKey(%s) failed", keyfile);
			break;
		}
		x509 = LoadCert(certfile, 0, out_msg);
		if (x509 == NULL) {
			sprintf(out_msg, "loadCert(%s) failed", certfile);
			break;
		}
		if (!X509_check_private_key(x509, prkey)) {
			sprintf(out_msg, "ca certificate and ca private key do not match");
			break;
		}

		const char *md = "sha256";
		//return an EVP_MD structure when passed a digest name
		if ((dgst = EVP_get_digestbyname(md)) == NULL) {
			sprintf(out_msg, "%s is an unsupported message digest type", md);
			break;
		}
		ok = certify(&x, req, prkey, x509, dgst, "today", enddate, days, KUSAGE, EKUSAGE, ca_enable,
			serial, common_name, cn_len, organization, o_len, email, mail_len, out_msg);
		if (ok <= 0) {
			break;
		}
		switch (type)
		{
		case DER:
			j = i2d_X509_bio(bcert, x);
			bret = true;
			break;
		case PEM:
			j = PEM_write_bio_X509(bcert, x);
			bret = true;
			break;
		default:
			strcpy(out_msg, "generate Cert File Error");
			break;
		}
	} while (false);

	if (bcert) BIO_free_all(bcert);
	if (reqbio) BIO_free_all(reqbio);
	if (prkey) EVP_PKEY_free(prkey);
	if (x509) X509_free(x509);
	if (x) X509_free(x);
	if (req) X509_REQ_free(req);
	EVP_cleanup();
	if (false == bret && utils::File::IsExist(outfile)) {
		utils::File::Delete(outfile);
	}
	return bret;
}

struct tm *CA::OPENSSL_gmtime(const time_t *timer, struct tm *result) {
	struct tm *ts = NULL;

#if defined(OPENSSL_THREADS) && !defined(OPENSSL_SYS_WIN32) && !defined(OPENSSL_SYS_OS2) && (!defined(OPENSSL_SYS_VMS) || defined(gmtime_r)) && !defined(OPENSSL_SYS_MACOSX) && !defined(OPENSSL_SYS_SUNOS)
	/*
	* should return &data, but doesn't on some systems, so we don't even
	* look at the return value
	*/
	gmtime_r(timer, result);
	ts = result;
#elif !defined(OPENSSL_SYS_VMS) || defined(VMS_GMTIME_OK)
	ts = gmtime(timer);
	if (ts == NULL)
		return NULL;

	memcpy(result, ts, sizeof(struct tm));
	ts = result;
#endif
#if defined( OPENSSL_SYS_VMS) && !defined( VMS_GMTIME_OK)
	if (ts == NULL) {
		static $DESCRIPTOR(tabnam, "LNM$DCL_LOGICAL");
		static $DESCRIPTOR(lognam, "SYS$TIMEZONE_DIFFERENTIAL");
		char logvalue[256];
		unsigned int reslen = 0;
# if __INITIAL_POINTER_SIZE == 64
		ILEB_64 itemlist[2], *pitem;
# else
		ILE3 itemlist[2], *pitem;
# endif
		int status;
		time_t t;


		/*
		* Setup an itemlist for the call to $TRNLNM - Translate Logical Name.
		*/
		pitem = itemlist;

# if __INITIAL_POINTER_SIZE == 64
		pitem->ileb_64$w_mbo = 1;
		pitem->ileb_64$w_code = LNM$_STRING;
		pitem->ileb_64$l_mbmo = -1;
		pitem->ileb_64$q_length = sizeof (logvalue);
		pitem->ileb_64$pq_bufaddr = logvalue;
		pitem->ileb_64$pq_retlen_addr = (unsigned __int64 *)&reslen;
		pitem++;
		/* Last item of the item list is null terminated */
		pitem->ileb_64$q_length = pitem->ileb_64$w_code = 0;
# else
		pitem->ile3$w_length = sizeof (logvalue);
		pitem->ile3$w_code = LNM$_STRING;
		pitem->ile3$ps_bufaddr = logvalue;
		pitem->ile3$ps_retlen_addr = (unsigned short int *) &reslen;
		pitem++;
		/* Last item of the item list is null terminated */
		pitem->ile3$w_length = pitem->ile3$w_code = 0;
# endif


		/* Get the value for SYS$TIMEZONE_DIFFERENTIAL */
		status = sys$trnlnm(0, &tabnam, &lognam, 0, itemlist);
		if (!(status & 1))
			return NULL;
		logvalue[reslen] = '\0';

		t = *timer;

		/* The following is extracted from the DEC C header time.h */
		/*
		**  Beginning in OpenVMS Version 7.0 mktime, time, ctime, strftime
		**  have two implementations.  One implementation is provided
		**  for compatibility and deals with time in terms of local time,
		**  the other __utc_* deals with time in terms of UTC.
		*/
		/*
		* We use the same conditions as in said time.h to check if we should
		* assume that t contains local time (and should therefore be
		* adjusted) or UTC (and should therefore be left untouched).
		*/
# if __CRTL_VER < 70000000 || defined _VMS_V6_SOURCE
		/* Get the numerical value of the equivalence string */
		status = atoi(logvalue);

		/* and use it to move time to GMT */
		t -= status;
# endif

		/* then convert the result to the time structure */

		/*
		* Since there was no gmtime_r() to do this stuff for us, we have to
		* do it the hard way.
		*/
		{
			/*-
			* The VMS epoch is the astronomical Smithsonian date,
			if I remember correctly, which is November 17, 1858.
			Furthermore, time is measure in thenths of microseconds
			and stored in quadwords (64 bit integers).  unix_epoch
			below is January 1st 1970 expressed as a VMS time.  The
			following code was used to get this number:

			#include <stdio.h>
			#include <stdlib.h>
			#include <lib$routines.h>
			#include <starlet.h>

			main()
			{
			unsigned long systime[2];
			unsigned short epoch_values[7] =
			{ 1970, 1, 1, 0, 0, 0, 0 };

			lib$cvt_vectim(epoch_values, systime);

			printf("%u %u", systime[0], systime[1]);
			}
			*/
			unsigned long unix_epoch[2] = { 1273708544, 8164711 };
			unsigned long deltatime[2];
			unsigned long systime[2];
			struct vms_vectime {
				short year, month, day, hour, minute, second, centi_second;
			} time_values;
			long operation;

			/*
			* Turn the number of seconds since January 1st 1970 to an
			* internal delta time. Note that lib$cvt_to_internal_time() will
			* assume that t is signed, and will therefore break on 32-bit
			* systems some time in 2038.
			*/
			operation = LIB$K_DELTA_SECONDS;
			status = lib$cvt_to_internal_time(&operation, &t, deltatime);

			/*
			* Add the delta time with the Unix epoch and we have the current
			* UTC time in internal format
			*/
			status = lib$add_times(unix_epoch, deltatime, systime);

			/* Turn the internal time into a time vector */
			status = sys$numtim(&time_values, systime);

			/* Fill in the struct tm with the result */
			result->tm_sec = time_values.second;
			result->tm_min = time_values.minute;
			result->tm_hour = time_values.hour;
			result->tm_mday = time_values.day;
			result->tm_mon = time_values.month - 1;
			result->tm_year = time_values.year - 1900;

			operation = LIB$K_DAY_OF_WEEK;
			status = lib$cvt_from_internal_time(&operation,
				&result->tm_wday, systime);
			result->tm_wday %= 7;

			operation = LIB$K_DAY_OF_YEAR;
			status = lib$cvt_from_internal_time(&operation,
				&result->tm_yday, systime);
			result->tm_yday--;

			result->tm_isdst = 0; /* There's no way to know... */

			ts = result;
		}
	}
#endif
	return ts;
}

long CA::date_to_julian(int y, int m, int d) {
	return (1461 * (y + 4800 + (m - 14) / 12)) / 4 +
		(367 * (m - 2 - 12 * ((m - 14) / 12))) / 12 -
		(3 * ((y + 4900 + (m - 14) / 12) / 100)) / 4 + d - 32075;
}

int CA::julian_adj(const struct tm *tm, int off_day, long offset_sec, long *pday, int *psec)
{
	int offset_hms, offset_day;
	long time_jd;
	int time_year, time_month, time_day;
	/* split offset into days and day seconds */
	offset_day = offset_sec / SECS_PER_DAY;
	/* Avoid sign issues with % operator */
	offset_hms = offset_sec - (offset_day * SECS_PER_DAY);
	offset_day += off_day;
	/* Add current time seconds to offset */
	offset_hms += tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
	/* Adjust day seconds if overflow */
	if (offset_hms >= SECS_PER_DAY) {
		offset_day++;
		offset_hms -= SECS_PER_DAY;
	}
	else if (offset_hms < 0) {
		offset_day--;
		offset_hms += SECS_PER_DAY;
	}

	/*
	* Convert date of time structure into a Julian day number.
	*/
	time_year = tm->tm_year + 1900;
	time_month = tm->tm_mon + 1;
	time_day = tm->tm_mday;

	time_jd = date_to_julian(time_year, time_month, time_day);

	/* Work out Julian day of new date */
	time_jd += offset_day;

	if (time_jd < 0)
		return 0;

	*pday = time_jd;
	*psec = offset_hms;
	return 1;
}

void CA::julian_to_date(long jd, int *y, int *m, int *d) {
	long L = jd + 68569;
	long n = (4 * L) / 146097;
	long i, j;

	L = L - (146097 * n + 3) / 4;
	i = (4000 * (L + 1)) / 1461001;
	L = L - (1461 * i) / 4 + 31;
	j = (80 * L) / 2447;
	*d = L - (2447 * j) / 80;
	L = j / 11;
	*m = j + 2 - (12 * L);
	*y = 100 * (n - 49) + i + L;
}

int CA::OPENSSL_gmtime_adj(struct tm *tm, int off_day, long offset_sec) {
	int time_sec, time_year, time_month, time_day;
	long time_jd;

	/* Convert time and offset into julian day and seconds */
	if (!julian_adj(tm, off_day, offset_sec, &time_jd, &time_sec))
		return 0;

	/* Convert Julian day back to date */
	julian_to_date(time_jd, &time_year, &time_month, &time_day);
	if (time_year < 1900 || time_year > 9999)
		return 0;

	/* Update tm structure */
	tm->tm_year = time_year - 1900;
	tm->tm_mon = time_month - 1;
	tm->tm_mday = time_day;

	tm->tm_hour = time_sec / 3600;
	tm->tm_min = (time_sec / 60) % 60;
	tm->tm_sec = time_sec % 60;

	return 1;

}

int CA::asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d) {
	static const int min[8] = { 0, 1, 1, 0, 0, 0, 0, 0 };
	static const int max[8] = { 99, 12, 31, 23, 59, 59, 12, 59 };
	char *a;
	int n, i, l, o;

	if (d->type != V_ASN1_UTCTIME)
		return (0);
	l = d->length;
	a = (char *)d->data;
	o = 0;

	if (l < 11)
		goto err;
	for (i = 0; i < 6; i++) {
		if ((i == 5) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
			i++;
			if (tm)
				tm->tm_sec = 0;
			break;
		}
		if ((a[o] < '0') || (a[o] > '9'))
			goto err;
		n = a[o] - '0';
		if (++o > l)
			goto err;

		if ((a[o] < '0') || (a[o] > '9'))
			goto err;
		n = (n * 10) + a[o] - '0';
		if (++o > l)
			goto err;

		if ((n < min[i]) || (n > max[i]))
			goto err;
		if (tm) {
			switch (i) {
			case 0:
				tm->tm_year = n < 50 ? n + 100 : n;
				break;
			case 1:
				tm->tm_mon = n - 1;
				break;
			case 2:
				tm->tm_mday = n;
				break;
			case 3:
				tm->tm_hour = n;
				break;
			case 4:
				tm->tm_min = n;
				break;
			case 5:
				tm->tm_sec = n;
				break;
			}
		}
	}
	if (a[o] == 'Z')
		o++;
	else if ((a[o] == '+') || (a[o] == '-')) {
		int offsign = a[o] == '-' ? -1 : 1, offset = 0;
		o++;
		if (o + 4 > l)
			goto err;
		for (i = 6; i < 8; i++) {
			if ((a[o] < '0') || (a[o] > '9'))
				goto err;
			n = a[o] - '0';
			o++;
			if ((a[o] < '0') || (a[o] > '9'))
				goto err;
			n = (n * 10) + a[o] - '0';
			if ((n < min[i]) || (n > max[i]))
				goto err;
			if (tm) {
				if (i == 6)
					offset = n * 3600;
				else if (i == 7)
					offset += n * 60;
			}
			o++;
		}
		if (offset && !OPENSSL_gmtime_adj(tm, 0, offset * offsign))
			return 0;
	}
	return o == l;
err:
	return 0;
}

int CA::asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d)
{
	static const int min[9] = { 0, 0, 1, 1, 0, 0, 0, 0, 0 };
	static const int max[9] = { 99, 99, 12, 31, 23, 59, 59, 12, 59 };
	char *a;
	int n, i, l, o;

	if (d->type != V_ASN1_GENERALIZEDTIME)
		return (0);
	l = d->length;
	a = (char *)d->data;
	o = 0;
	/*
	* GENERALIZEDTIME is similar to UTCTIME except the year is represented
	* as YYYY. This stuff treats everything as a two digit field so make
	* first two fields 00 to 99
	*/
	if (l < 13)
		goto err;
	for (i = 0; i < 7; i++) {
		if ((i == 6) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
			i++;
			if (tm)
				tm->tm_sec = 0;
			break;
		}
		if ((a[o] < '0') || (a[o] > '9'))
			goto err;
		n = a[o] - '0';
		if (++o > l)
			goto err;

		if ((a[o] < '0') || (a[o] > '9'))
			goto err;
		n = (n * 10) + a[o] - '0';
		if (++o > l)
			goto err;

		if ((n < min[i]) || (n > max[i]))
			goto err;
		if (tm) {
			switch (i) {
			case 0:
				tm->tm_year = n * 100 - 1900;
				break;
			case 1:
				tm->tm_year += n;
				break;
			case 2:
				tm->tm_mon = n - 1;
				break;
			case 3:
				tm->tm_mday = n;
				break;
			case 4:
				tm->tm_hour = n;
				break;
			case 5:
				tm->tm_min = n;
				break;
			case 6:
				tm->tm_sec = n;
				break;
			}
		}
	}
	/*
	* Optional fractional seconds: decimal point followed by one or more
	* digits.
	*/
	if (a[o] == '.') {
		if (++o > l)
			goto err;
		i = o;
		while ((a[o] >= '0') && (a[o] <= '9') && (o <= l))
			o++;
		/* Must have at least one digit after decimal point */
		if (i == o)
			goto err;
	}

	if (a[o] == 'Z')
		o++;
	else if ((a[o] == '+') || (a[o] == '-')) {
		int offsign = a[o] == '-' ? -1 : 1, offset = 0;
		o++;
		if (o + 4 > l)
			goto err;
		for (i = 7; i < 9; i++) {
			if ((a[o] < '0') || (a[o] > '9'))
				goto err;
			n = a[o] - '0';
			o++;
			if ((a[o] < '0') || (a[o] > '9'))
				goto err;
			n = (n * 10) + a[o] - '0';
			if ((n < min[i]) || (n > max[i]))
				goto err;
			if (tm) {
				if (i == 7)
					offset = n * 3600;
				else if (i == 8)
					offset += n * 60;
			}
			o++;
		}
		if (offset && !OPENSSL_gmtime_adj(tm, 0, offset * offsign))
			return 0;
	}
	else if (a[o]) {
		/* Missing time zone information. */
		goto err;
	}
	return (o == l);
err:
	return (0);
}

int CA::asn1_time_to_tm(struct tm *tm, const ASN1_TIME *t) {
	if (t == NULL) {
		time_t now_t;
		time(&now_t);
		if (OPENSSL_gmtime(&now_t, tm))
			return 1;
		return 0;
	}

	if (t->type == V_ASN1_UTCTIME)
		return asn1_utctime_to_tm(tm, t);
	else if (t->type == V_ASN1_GENERALIZEDTIME)
		return asn1_generalizedtime_to_tm(tm, t);

	return 0;
}

bool CA::mkRoot(stuSUBJECT *rootInfo, X509 **x509p, RSA **rsa, EVP_PKEY **ppkey, int bits, int days, char *out_msg) {
	bool bret = false;
	do {
		X509 *x;
		EVP_PKEY *pk;
		X509_NAME *name = NULL;
		int i = 0, len = 0;
		if ((ppkey == NULL) || (*ppkey == NULL)) {
			if ((pk = EVP_PKEY_new()) == NULL) {
				break;
			}
		}
		else
			pk = *ppkey;
		if ((x509p == NULL) || (*x509p == NULL)) {
			if ((x = X509_new()) == NULL)
				break;
		}
		else {
			x = *x509p;
		}

		Rand(NULL, 1, out_msg);
		*rsa = RSA_generate_key(bits, RSA_3, 0, NULL);
		if (!EVP_PKEY_assign_RSA(pk, *rsa)) {
			break;
		}

		X509_set_version(x, 2);
		ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
		ASN1_TIME* not_before_time = X509_gmtime_adj(X509_get_notBefore(x), 0);
		struct tm tm_not_before;
		char not_before[20] = { 0 };
		if (asn1_time_to_tm(&tm_not_before, not_before_time) == 1) {
			sprintf(not_before, "%04d%02d%02d%02d%02d%02d", tm_not_before.tm_year + 1900, tm_not_before.tm_mon + 1, tm_not_before.tm_mday,
				(tm_not_before.tm_hour + 8 >= 24 ? (tm_not_before.tm_hour - 16) : (tm_not_before.tm_hour + 8)), tm_not_before.tm_min, tm_not_before.tm_sec);
		}
		ASN1_TIME* not_after_time = X509_gmtime_adj(X509_get_notAfter(x), (long)SECS_PER_DAY * days);
		struct tm tm_not_after;
		char not_after[20] = { 0 };
		if (asn1_time_to_tm(&tm_not_after, not_after_time) == 1) {
			sprintf(not_after, "%04d%02d%02d%02d%02d%02d", tm_not_after.tm_year + 1900, tm_not_after.tm_mon + 1, tm_not_after.tm_mday,
				(tm_not_after.tm_hour + 8 >= 24 ? (tm_not_after.tm_hour - 16) : (tm_not_after.tm_hour + 8)), tm_not_after.tm_min, tm_not_after.tm_sec);
		}

		X509_set_pubkey(x, pk);

		// add subject
		name = X509_get_subject_name(x);
		setlocale(LC_CTYPE, "");
		Add_Name(name, NID_countryName, (char *)rootInfo->C, sizeof(rootInfo->C), out_msg);
		Add_Name(name, NID_stateOrProvinceName, (char *)rootInfo->ST, sizeof(rootInfo->ST), out_msg);
		Add_Name(name, NID_localityName, (char *)rootInfo->L, sizeof(rootInfo->L), out_msg);
		Add_Name(name, NID_organizationName, (char *)rootInfo->O, sizeof(rootInfo->O), out_msg);
		Add_Name(name, NID_organizationalUnitName, (char *)rootInfo->OU, sizeof(rootInfo->OU), out_msg);
		Add_Name(name, NID_commonName, (char *)rootInfo->CN, sizeof(rootInfo->CN), out_msg);
		Add_Name(name, NID_pkcs9_emailAddress, (char *)rootInfo->MAIL, sizeof(rootInfo->MAIL), out_msg);
		Add_Name(name, NID_email_protect, (char *)rootInfo->PMAIL, sizeof(rootInfo->PMAIL), out_msg);
		Add_Name(name, NID_title, (char *)rootInfo->T, sizeof(rootInfo->T), out_msg);
		Add_Name(name, NID_description, (char *)rootInfo->D, sizeof(rootInfo->D), out_msg);
		Add_Name(name, NID_givenName, (char *)rootInfo->G, sizeof(rootInfo->G), out_msg);
		Add_Name(name, NID_initials, (char *)rootInfo->I, sizeof(rootInfo->I), out_msg);
		Add_Name(name, NID_name, (char *)rootInfo->NAME, sizeof(rootInfo->NAME), out_msg);
		Add_Name(name, NID_surname, (char *)rootInfo->S, sizeof(rootInfo->S), out_msg);
		Add_Name(name, NID_dnQualifier, (char *)rootInfo->QUAL, sizeof(rootInfo->QUAL), out_msg);
		Add_Name(name, NID_pkcs9_unstructuredName, (char *)rootInfo->STN, sizeof(rootInfo->STN), out_msg);
		Add_Name(name, NID_pkcs9_challengePassword, (char *)rootInfo->PW, sizeof(rootInfo->PW), out_msg);
		Add_Name(name, NID_pkcs9_unstructuredAddress, (char *)rootInfo->ADD, sizeof(rootInfo->ADD), out_msg);
		X509_set_issuer_name(x, name);

		// extensions
		Add_ExtCert(x, x, NID_basic_constraints, "critical,CA:TRUE");
		Add_ExtCert(x, x, NID_subject_key_identifier, "hash");
		Add_ExtCert(x, x, NID_authority_key_identifier, "keyid:always");
		//Add_ExtCert(x, x, NID_key_usage, "nonRepudiation,digitalSignature,keyEncipherment,keyCertSign");
		Add_ExtCert(x, x, NID_domainComponent, "no");
		Add_ExtCert(x, x, NID_Domain, "no");

		// add self extensions, root code
		int nid;
		std::string root_code;
		mkRootCode(rootInfo, not_before, not_after, root_code);
		nid = OBJ_create("1.12.30663.195.6325", "root_code", "Root Code");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		Add_ExtCert(x, x, nid, root_code.c_str());
		X509V3_EXT_cleanup();
		if (!X509_sign(x, pk, EVP_sha256())) {
			strcpy(out_msg, "sign certificate failed");
			break;
		}
		*x509p = x;
		*ppkey = pk;
		bret = true;
	} while (false);

	return bret;
}

bool CA::CheckRootCert(const char *root_file_path, char *root_ext_code, int root_ext_len, char *out_msg) {
	bool bret = false;
	X509 *x509 = NULL;
	do {
		x509 = LoadCert(root_file_path, 0, out_msg);
		if (x509 == NULL) {
			break;
		}

		bret = CheckRootCert(x509, root_ext_code, root_ext_len, out_msg);
	} while (false);

	if (x509) X509_free(x509);
	return bret;
}

bool CA::CheckRootCert(X509 *x509, char *root_ext_code, int root_ext_len, char *err_msg) {
	bool bret = false;
	do {
		if (NULL == x509) {
			sprintf(err_msg, "the handle of the certificate is null");
			break;
		}
		if (NULL == root_ext_code) {
			sprintf(err_msg, "the buffer of the root code is null");
			break;
		}
		X509_NAME *name = X509_get_subject_name(x509);
		// get subject
		stuSUBJECT root_info;
		X509_NAME_get_text_by_NID(name, NID_organizationName, (char *)root_info.O, sizeof(root_info.O));
		X509_NAME_get_text_by_NID(name, NID_commonName, (char *)root_info.CN, sizeof(root_info.CN));
		X509_NAME_get_text_by_NID(name, NID_pkcs9_emailAddress, (char *)root_info.MAIL, sizeof(root_info.MAIL));
		X509_NAME_get_text_by_NID(name, NID_countryName, (char *)root_info.C, sizeof(root_info.C));
		X509_NAME_get_text_by_NID(name, NID_stateOrProvinceName, (char *)root_info.ST, sizeof(root_info.ST));
		X509_NAME_get_text_by_NID(name, NID_localityName, (char *)root_info.L, sizeof(root_info.L));
		X509_NAME_get_text_by_NID(name, NID_organizationalUnitName, (char *)root_info.OU, sizeof(root_info.OU));
		X509_NAME_get_text_by_NID(name, NID_title, (char *)root_info.T, sizeof(root_info.T));

		// check the validity
		char not_before[20] = { 0 };
		char not_after[20] = { 0 };
		if (false == CheckCertValidity(x509, not_before, not_after, err_msg)) {
			break;
		}

		// get root_code
		if (false == GetRootCode(x509, root_ext_code, root_ext_len, err_msg)) {
			break;
		}
		// make root code
		std::string root_code;
		mkRootCode(&root_info, not_before, not_after, root_code);

		if (root_code.compare(root_ext_code) != 0) {
			sprintf(err_msg, "the value of the extension (1.12.30663.195.6325) is invalid");
			break;
		}

		bret = true;
	} while (false);

	return bret;
}

bool CA::CheckEntityCert(const char *issuer_cert_file, const char *subject_cert_file, const char *key_file, const char *password, char *out_msg) {
	bool bret = false;
	X509 *issuer_x509 = NULL, *subject_x509 = NULL;
	EVP_PKEY *prkey = NULL;
	do {
		issuer_x509 = LoadCert(issuer_cert_file, 0, out_msg);
		if (issuer_x509 == NULL) {
			break;
		}
		subject_x509 = LoadCert(subject_cert_file, 0, out_msg);
		if (subject_x509 == NULL) {
			break;
		}

		if (X509_check_issued(issuer_x509, subject_x509) != X509_V_OK) {
			sprintf(out_msg, "the root certificate(%s) is not the issuer of entity certificate(%s)", issuer_cert_file, subject_cert_file);
			break;
		}
		prkey = LoadKey(key_file, 0, password, out_msg);
		if (prkey == NULL) {
			break;
		}
		if (!X509_check_private_key(subject_x509, prkey)) {
			sprintf(out_msg, "certificate and private key do not match");
			break;
		}
		if (!CheckCertValidity(subject_x509, NULL, NULL, out_msg)) {
			break;
		}
		bret = true;
	} while (false);

	if (issuer_x509) X509_free(issuer_x509);
	if (subject_x509) X509_free(subject_x509);
	if (prkey) EVP_PKEY_free(prkey);
	return bret;
}

bool CA::GetCertSerial(const char *certfile, char *serial, char *out_msg) {
	bool bret = false;
	X509 *x509 = NULL;
	BIGNUM *serial_num = NULL;
	do {
		x509 = LoadCert(certfile, 0, out_msg);
		if (x509 == NULL) {
			sprintf(out_msg, "load ca %s failed", certfile);
			break;
		}
		OpenSSL_add_all_digests();
		ASN1_INTEGER *ai = NULL;
		if ((ai = X509_get_serialNumber(x509)) == NULL) {
			strcpy(out_msg, "X509_get_serialNumber failed");
			break;
		}
		serial_num = BN_new();
		if (ASN1_INTEGER_to_BN(ai, serial_num) == NULL) {
			strcpy(out_msg, "ASN1_INTEGER_to_BN failed");
			break;
		}
		strcpy(serial, BN_bn2hex(serial_num));
		bret = true;
	} while (false);
	if (x509) X509_free(x509);
	if (serial_num) BN_free(serial_num);
	return bret;
}

bool CA::GetCertSerial(X509 *x509, char *serial, char *out_msg) {
	bool bret = false;
	BIGNUM *serial_num = NULL;
	do {
		if (NULL == x509) {
			sprintf(out_msg, "the handle of the certificate is null");
			break;
		}
		if (NULL == out_msg) {
			break;
		}
		OpenSSL_add_all_digests();
		ASN1_INTEGER *ai = NULL;
		if ((ai = X509_get_serialNumber(x509)) == NULL) {
			strcpy(out_msg, "X509_get_serialNumber failed");
			break;
		}
		serial_num = BN_new();
		if (ASN1_INTEGER_to_BN(ai, serial_num) == NULL) {
			strcpy(out_msg, "ASN1_INTEGER_to_BN failed");
			break;
		}
		strcpy(serial, BN_bn2hex(serial_num));
		bret = true;
	} while (false);

	if (serial_num) BN_free(serial_num);
	return bret;
}

bool CA::GetReqContent(const char *reqfile, stuSUBJECT& reqInfo, char *out_msg) {
	bool bret = false;
	X509_REQ *req = NULL;
	BIO *reqbio = NULL;
	do {
		OpenSSL_add_all_digests();
		if ((reqbio = BIO_new_file(reqfile, "r")) == NULL) {
			sprintf(out_msg, "open request file(%s) failed", reqfile);
			break;
		}
		if ((req = PEM_read_bio_X509_REQ(reqbio, NULL, NULL, NULL)) == NULL) {
			sprintf(out_msg, "read request file failed");
			break;
		}

		X509_NAME *name = X509_REQ_get_subject_name(req);
		// get subject
		X509_NAME_get_text_by_NID(name, NID_organizationName, (char *)reqInfo.O, sizeof(reqInfo.O));
		X509_NAME_get_text_by_NID(name, NID_commonName, (char *)reqInfo.CN, sizeof(reqInfo.CN));
		X509_NAME_get_text_by_NID(name, NID_pkcs9_emailAddress, (char *)reqInfo.MAIL, sizeof(reqInfo.MAIL));
		X509_NAME_get_text_by_NID(name, NID_countryName, (char *)reqInfo.C, sizeof(reqInfo.C));
		X509_NAME_get_text_by_NID(name, NID_stateOrProvinceName, (char *)reqInfo.ST, sizeof(reqInfo.ST));
		X509_NAME_get_text_by_NID(name, NID_localityName, (char *)reqInfo.L, sizeof(reqInfo.L));
		X509_NAME_get_text_by_NID(name, NID_organizationalUnitName, (char *)reqInfo.OU, sizeof(reqInfo.OU));
		X509_NAME_get_text_by_NID(name, NID_title, (char *)reqInfo.T, sizeof(reqInfo.T));

		// get ext
		if (!GetHDAndDA(req, reqInfo.HD, sizeof(reqInfo.HD), reqInfo.NI, sizeof(reqInfo.NI), out_msg)) {
			break;
		}
		bret = true;
	} while (false);
	if (reqbio) BIO_free(reqbio);
	if (req) X509_REQ_free(req);
	return bret;
}

bool CA::GetHDAndDA(const char *file_path, char *hardware_address, int hard_len, char *node_id, int id_len, char *out_msg) {
	bool bret = false; 
	do {
		if (!GetCertHDAndDA(file_path, hardware_address, hard_len, node_id, id_len, out_msg)) {
			bret = GetReqHDAndDA(file_path, hardware_address, hard_len, node_id, id_len, out_msg);
			break;
		}
		bret = true;
	} while (false);
	return bret;
}

bool CA::GetHDAndDA(X509 *x509, char *hardware_address, int hard_len, char *node_id, int id_len, char *out_msg) {
	bool bret = false;
	do {
		if (NULL == x509) {
			sprintf(out_msg, "the handle of the certificate is null");
			break;
		}
		if (NULL == out_msg) {
			break;
		}
		// node id
		if (!GetExtensionData(x509, "1.1.1.1", "node_id", "Node Id", node_id, id_len, out_msg)) {
			break;
		}
		// hardware address
		if (!GetExtensionData(x509, "1.1.1.2", "hard_address", "Hared Address", hardware_address, hard_len, out_msg)) {
			break;
		}
		bret = true;
	} while (false);
	return bret;
}

bool CA::GetHDAndDA(X509_REQ *req, char *hardware_address, int hard_len, char *node_id, int id_len, char *out_msg) {
	bool bret = false;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	do {
		OpenSSL_add_all_digests();
		if (NULL == req) {
			sprintf(out_msg, "the handle of the request certificate is null");
			break;
		}
		if (NULL == hardware_address || NULL == node_id || NULL == out_msg) {
			sprintf(out_msg, "the buffer is null");
			break;
		}
		EVP_PKEY *pktmp = NULL;
		int ok = -1, i = 0;
		if ((pktmp = X509_REQ_get_pubkey(req)) == NULL) {
			sprintf(out_msg, "unpack public key failed");
			break;
		}
		// check signature  
		i = X509_REQ_verify(req, pktmp);
		EVP_PKEY_free(pktmp);
		if (i < 0) {
			sprintf(out_msg, "signature verification problems");
			break;
		}
		if (i == 0) {
			sprintf(out_msg, "signature did not match the certificate request");
			break;
		}
		exts = X509_REQ_get_extensions(req);
		int nid_node_id = OBJ_create("1.1.1.1", "node_id", "Node Id");
		int nid_hard_addr = OBJ_create("1.1.1.2", "hard_address", "Hared Address");
		bool bsuccess = true;
		for (int idx = 0; idx < sk_X509_EXTENSION_num(exts); idx++) {
			X509_EXTENSION *ext = NULL;
			ext = sk_X509_EXTENSION_value(exts, idx);
			ASN1_OCTET_STRING *octet_str = X509_EXTENSION_get_data(ext);
			if (OBJ_obj2nid(ext->object) == nid_node_id) {
				uint32_t data_len = strlen((char *)&octet_str->data[2]);
				if ((unsigned)id_len < data_len) {
					bsuccess = false;
					sprintf(out_msg, "the length of hardware address buffer is too small");
					break;
				}
				strcpy(node_id, (char *)&octet_str->data[2]);
			}
			else if (OBJ_obj2nid(ext->object) == nid_hard_addr) {
				printf("%s\n", (char *)&octet_str->data[2]);
				uint32_t data_len = strlen((char *)&octet_str->data[2]);
				if ((unsigned)hard_len < data_len) {
					bsuccess = false;
					sprintf(out_msg, "the length of node id buffer is too small");
					break;
				}
				strcpy(hardware_address, (char *)&octet_str->data[2]);
			}
		}

		if (false == bsuccess) break;
		bret = true;
	} while (false);
	return bret;
}

bool CA::GetCAEnabled(const char *cert_file, bool& cert_enabled, char *out_msg) {
	bool bret = false;
	X509 *x509 = NULL;
	do {
		if (NULL == out_msg) {
			break;
		}
		OpenSSL_add_all_digests();
		x509 = LoadCert(cert_file, 0, out_msg);
		if (x509 == NULL) {
			sprintf(out_msg, "load ca %s failed", cert_file);
			break;
		}
		char ca_status[10] = { 0 };
		if (!GetExtensionData(x509, "1.1.1.3", "use_ca", "Use CA", ca_status, sizeof(ca_status), out_msg)) {
			break;
		}
		cert_enabled = (strcmp(ca_status, "true") == 0 ? true : false);
		bret = true;
	} while (false);
	if (x509) X509_free(x509);
	return bret;
}

bool CA::GetReqHDAndDA(const char *reqfile, char *hardware_address, int hard_len, char *node_id, int id_len, char *out_msg) {
	bool bret = false;
	X509_REQ *req = NULL;
	BIO *reqbio = NULL;
	do {
		OpenSSL_add_all_digests();
		if ((reqbio = BIO_new_file(reqfile, "r")) == NULL) {
			sprintf(out_msg, "open request file(%s) failed", reqfile);
			break;
		}
		BIO_set_close(reqbio, BIO_CLOSE);
		if ((req = PEM_read_bio_X509_REQ(reqbio, NULL, NULL, NULL)) == NULL) {
			BIO_reset(reqbio);
			if ((req = d2i_X509_REQ_bio(reqbio, NULL)) == NULL) {
				sprintf(out_msg, "read request certificate(%s) failed", reqfile);
				break;
			}
		}
		bret = GetHDAndDA(req, hardware_address, hard_len, node_id, id_len, out_msg);
	} while (false);
	if (reqbio) BIO_free(reqbio);
	if (req) X509_REQ_free(req);
	return bret;
}

bool CA::GetCertHDAndDA(const char *certfile, char *hardware_address, int hard_len, char *node_id, int id_len, char *out_msg) {
	bool bret = false;
	X509 *x509 = NULL;
	do {
		if (NULL == out_msg) {
			break;
		}
		OpenSSL_add_all_digests();
		x509 = LoadCert(certfile, 0, out_msg);
		if (x509 == NULL) {
			sprintf(out_msg, "load ca %s failed", certfile);
			break;
		}
		bret = GetHDAndDA(x509, hardware_address, hard_len, node_id, id_len, out_msg);
	} while (false);
	if (x509) X509_free(x509);
	return bret;
}

bool CA::GetExtensionData(X509 *x509, const char *oid, const char *sn, const char *ln, char *data, unsigned int len, char *out_msg) {
	bool bret = false;
	X509_EXTENSION *ext = NULL;
	do {
		if (NULL == data || NULL == x509) {
			sprintf(out_msg, "the buffer is null");
			break;
		}
		OpenSSL_add_all_digests();
		int nid = OBJ_create(oid, sn, ln);
		int idx = X509_get_ext_by_NID(x509, nid, -1);
		if (-1 == idx) {
			sprintf(out_msg, "not contain this extension (%s)", oid);
			break;
		}
		ext = X509_get_ext(x509, idx);
		if (NULL == ext) {
			sprintf(out_msg, "X509_get_ext %d failed", idx);
			break;
		}
		ASN1_OCTET_STRING *octet_str = X509_EXTENSION_get_data(ext);
		if (NULL == octet_str || NULL == octet_str->data) {
			sprintf(out_msg, "X509_EXTENSION_get_data failed");
			break;
		}
		if (len < strlen((char *)&octet_str->data[2])) {
			sprintf(out_msg, "the length of buffer is too small");
			break;
		}
		strcpy(data, (char *)&octet_str->data[2]);
		bret = true;
	} while (false);

	return bret;
}

bool CA::CheckCertValidity(X509 *x509, char *not_before, char *not_after, char *out_msg) {
	bool bret = false;
	do {
		if (NULL == x509) {
			sprintf(out_msg, "certificate can not be null");
			break;
		}

		ASN1_TIME* not_before_time = X509_get_notBefore(x509);
		struct tm tm_not_before;
		if (asn1_time_to_tm(&tm_not_before, not_before_time) != 1) {
			sprintf(out_msg, "parse begin time failed, maybe the certificate is broken");
			break;
		}

		ASN1_TIME* not_after_time = X509_get_notAfter(x509);
		struct tm tm_not_after;
		if (asn1_time_to_tm(&tm_not_after, not_after_time) != 1) {
			sprintf(out_msg, "parse end time failed, maybe the certificate is broken");
			break;
		}

		time_t now = time(NULL);
		time_t before = mktime(&tm_not_before);
		time_t after = mktime(&tm_not_after);
		if (now <= before) {
			sprintf(out_msg, "the begin time of the certificate can not later than the current time");
			break;
		}
		if (now >= after) {
			sprintf(out_msg, "the end time of the certificate can not earlier than the current time");
			break;
		}

		if (not_before != NULL) {
			sprintf(not_before, "%04d%02d%02d%02d%02d%02d", tm_not_before.tm_year + 1900, tm_not_before.tm_mon + 1, tm_not_before.tm_mday,
				(tm_not_before.tm_hour + 8 >= 24 ? (tm_not_before.tm_hour - 16) : (tm_not_before.tm_hour + 8)), tm_not_before.tm_min, tm_not_before.tm_sec);
		}
		
		if (not_after != NULL) {
			sprintf(not_after, "%04d%02d%02d%02d%02d%02d", tm_not_after.tm_year + 1900, tm_not_after.tm_mon + 1, tm_not_after.tm_mday,
				(tm_not_after.tm_hour + 8 >= 24 ? (tm_not_after.tm_hour - 16) : (tm_not_after.tm_hour + 8)), tm_not_after.tm_min, tm_not_after.tm_sec);
		}

		bret = true;
	} while (false);

	return bret;
}

}