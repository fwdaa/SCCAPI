#include "pch.h"
#include "ui.h"
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#include "TraceWindows.h"
#include "TraceOpenSSL.h"
#ifdef WPP_CONTROL_GUIDS
#include "Aladdin.CAPI.OpenSSL.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� Base-64
///////////////////////////////////////////////////////////////////////////////
template <>
std::string Aladdin::CAPI::OpenSSL::EncodeBase64<char>(const void* pvData, size_t cbData)
{$
	// �������� ����� ���������� �������
	std::string encoded((cbData + 2) / 3 * 4, 0); unsigned char encodedBlock[66]; 

	// ��� ���� ������ �� 48-������
	size_t i; for (i = 0; cbData >= 48; cbData -= 48, i++)
	{
		// ������������ ����� ������
		::EVP_EncodeBlock(encodedBlock, (unsigned char*)pvData, 48); 

		// ����������� �������������� ������
		memcpy(&encoded[i * 64], encodedBlock, 64); 

		// ������� �� ��������� ���� ������
		pvData = (const unsigned char*)pvData + 48; 
	}
	if (cbData > 0)
	{
		// ������������ ����� ������
		::EVP_EncodeBlock(encodedBlock, (unsigned char*)pvData, (int)cbData); 

		// ����������� �������������� ������
		memcpy(&encoded[i * 64], encodedBlock, (cbData + 2) / 3 * 4);
	}
	return encoded; 
}

template <>
std::wstring Aladdin::CAPI::OpenSSL::EncodeBase64<wchar_t>(const void* pvData, size_t cbData)
{$
	// ������������ ������ � ��������� Base-64
	std::string encoded = EncodeBase64<char>(pvData, cbData); 

	// ��������� �������������� ���������
	return to_unicode(encoded.c_str(), encoded.size()); 
}
// ��������������� �������
template std::wstring Aladdin::CAPI::OpenSSL::EncodeBase64<wchar_t>(const void*, size_t); 

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::DecodeBase64(const char* szEncoded, size_t cch)
{$
	// ���������� ������ ������
	if (cch == (size_t)(-1)) { cch = strlen(szEncoded); } unsigned char decodedBlock[48];

	// �������� ����� ���������� �������
	std::vector<unsigned char> decoded((cch + 3) / 4 * 3, 0); 

	// ��� ���� ������ �� 64-�����
	size_t i; for (i = 0; cch >= 64; cch -= 64, i++, szEncoded += 64)
	{
		// ������������� ���� ������
		int cb = ::EVP_DecodeBlock(decodedBlock, (const unsigned char*)szEncoded, 64); 

		// ��������� ���������� ������
		if (cb < 0) { AE_CHECK_OPENSSL(0); }

		// ����������� ��������������� ������
		memcpy(&decoded[i * 48], decodedBlock, 48); 
	}
	if (cch != 0) 
	{  
		// ������������� ���� ������
		int cb = ::EVP_DecodeBlock(decodedBlock, (const unsigned char*)szEncoded, (int)cch); 

		// ��������� ���������� ������
		if (cb < 0) { AE_CHECK_OPENSSL(0); }

		// ����������� ��������������� ������
		memcpy(&decoded[i * 48], decodedBlock, cb); 

		// ������� ����������
		if (cch >= 2 && szEncoded[cch - 2] == '=') decoded.resize(decoded.size() - 2); else 
		if (cch >= 1 && szEncoded[cch - 1] == '=') decoded.resize(decoded.size() - 1);
	}
	return decoded; 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::DecodeBase64(const wchar_t* szEncoded, size_t cch)
{$
	// ��������� �������������� ���������
	std::string encoded = from_unicode(szEncoded, cch); 

	// ������������� ������ �� ��������� Base-64
	return DecodeBase64(encoded.c_str(), encoded.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ �������� ����������
///////////////////////////////////////////////////////////////////////////////
static const EVP_CIPHER* GetCipher(int keyNID, ENGINE** ppEngine)
{$
	// ��� ������ GOST
	if (keyNID == NID_id_GostR3410_94       || keyNID == NID_id_GostR3410_2001     || 
	    keyNID == NID_id_GostR3410_2012_256 || keyNID == NID_id_GostR3410_2012_512)
	{
		// �������� ������ ��� ���������
		*ppEngine = ::ENGINE_get_cipher_engine(NID_id_Gost28147_89); 

		// ��������� ������� �������
		if (!*ppEngine) AE_CHECK_OPENSSL(0); 
		try {
			// �������� ��������
			const EVP_CIPHER* pCipher = ::ENGINE_get_cipher(
				*ppEngine, NID_id_Gost28147_89
			); 
			// ��������� ������� ���������
			if (!pCipher) AE_CHECK_OPENSSL(0); return pCipher;
		}
		// ���������� ���������� �������
		catch (...) { ::ENGINE_finish(*ppEngine); throw; }
	}
	// ��� ������ ECC-256
	if (keyNID == NID_X9_62_prime256v1 ||
	    keyNID == NID_X9_62_c2pnb272w1 || 
	    keyNID == NID_X9_62_c2pnb304w1 ||
	    keyNID == NID_X9_62_c2tnb359v1 || 
	    keyNID == NID_X9_62_c2pnb368w1 ||  
	    keyNID == NID_secp256k1        ||
	    keyNID == NID_sect283r1		   || 
	    keyNID == NID_sect283k1 	    )
	{ 
		// ������� �������� AES-CBC
		*ppEngine = NULL; return ::EVP_aes_128_cbc(); 
	}
	// ��� ������ ECC-384
	if (keyNID == NID_X9_62_c2tnb431r1	|| 
	    keyNID == NID_secp384r1			|| 
	    keyNID == NID_sect409k1			|| 
	    keyNID == NID_sect409r1			 ) 
	{ 
		// ������� �������� AES-CBC
		*ppEngine = NULL; return ::EVP_aes_192_cbc(); 
	}
	// ��� ������ ECC-512
	if (keyNID == NID_secp521r1 || 
	    keyNID == NID_sect571k1 || 
	    keyNID == NID_sect571r1) 
	{ 
		// ������� �������� AES-CBC
		*ppEngine = NULL; return ::EVP_aes_256_cbc(); 
	}
	// ������� �������� TDES-CBC
	*ppEngine = NULL; return ::EVP_des_ede3_cbc(); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ���
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::DistinctName::DistinctName(X509_NAME* pName)
{$
	// ����� ����������� ������
	unsigned char* bufferEncoded = NULL;

	// ������������ ��� �������� 
	int cb = ::i2d_X509_NAME(pName, &bufferEncoded); 

	// ��������� ���������� ������
	if (cb < 0) AE_CHECK_OPENSSL(0); 
	try {
		// ����������� �������������� �������������
		encoded = std::vector<unsigned char>(
			bufferEncoded, bufferEncoded + cb
		); 
		// ���������� ���������� ������
		OPENSSL_free(bufferEncoded); 
	}
	// ���������� ���������� ������
	catch (...) { OPENSSL_free(bufferEncoded); throw; }

	// �������� ��������� ������������� �����
	char* bufferName = ::X509_NAME_oneline(pName, NULL, 0);

	// ��������� ���������� ������
	AE_CHECK_OPENSSL(bufferName); 
	try { 
		// ��������� ��������� ������������� �����
		name = to_unicode(bufferName); 

		// ���������� ���������� ������
		OPENSSL_free(bufferName); 
	}
	// ���������� ���������� ������
	catch (...) { OPENSSL_free(bufferName); throw; }
}
// ����������
Aladdin::CAPI::OpenSSL::DistinctName::~DistinctName() {$}

///////////////////////////////////////////////////////////////////////////////
// ���������� ��������� �����
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Aladdin::CAPI::OpenSSL::Certificate> 
Aladdin::CAPI::OpenSSL::Certificate::Decode(const void* pvEncoded, size_t cbEncoded) 
{$ 
	// ��������� �������������� ����
	const unsigned char* p = (const unsigned char*)pvEncoded;

	// ������������� ����������
	X509* pCertificateX509 = ::d2i_X509(NULL, &p, (long)(ptrdiff_t)cbEncoded);

	// ��������� ���������� ������
	AE_CHECK_OPENSSL(pCertificateX509); 
	try { 
		// ������� ������ �����������
		std::shared_ptr<CAPI::OpenSSL::Certificate> pCertificate(
			new Certificate(pCertificateX509)
		); 
		// ���������� ���������� ������ 
		::X509_free(pCertificateX509); return pCertificate; 
	}
	// ���������� ���������� ������ 
	catch (...) { ::X509_free(pCertificateX509); throw; }
}

Aladdin::CAPI::OpenSSL::Certificate::Certificate(X509* pCertificateX509) 
{$ 
	// �������� �������� ���� �����������
	X509_PUBKEY* pPublicKey = ::X509_get_X509_PUBKEY(pCertificateX509); 

	// ���������������� ����������
	ASN1_OBJECT* pObjectIdentifier = NULL; 

	// ������� ��������� ��������� �����
	::X509_PUBKEY_get0_param(&pObjectIdentifier, NULL, NULL, NULL, pPublicKey); 

	// �������� �������� �������������� ��������� �����
	keyNID = ::OBJ_obj2nid(pObjectIdentifier);

	// ��������� ���������� ������
	if (keyNID == NID_undef) AE_CHECK_OPENSSL(0); 

	// ��������� ������� ������
	AE_CHECK_OPENSSL(::X509_up_ref(pCertificateX509)); 
	try { 
		// ������� ������ ������������
		pCertificatesX509 = ::sk_X509_new_reserve(NULL, 1);  

		// ��������� ���������� ������
		AE_CHECK_OPENSSL(pCertificatesX509); 
	
		// �������� ���������� � ������
		::sk_X509_push(pCertificatesX509, pCertificateX509);
	}
	// ���������� ���������� ������ 
	catch (...) { ::X509_free(pCertificateX509); throw; }
}

Aladdin::CAPI::OpenSSL::Certificate::~Certificate() 
{$
	// ���������� ���������� ������
	::sk_X509_pop_free(pCertificatesX509, ::X509_free); 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Certificate::Encoded() const
{$
	// �������� ������������ ����������
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// ����� ����������� ������
	unsigned char* buffer = NULL;

	// ������������ ���������� 
	int cb = ::i2d_X509(pCertificateX509, &buffer); 

	// ��������� ���������� ������
	if (cb < 0) AE_CHECK_OPENSSL(0); 
	try {
		// ����������� �������������� �������������
		std::vector<unsigned char> encoded(buffer, buffer + cb); 

		// ���������� ���������� ������
		OPENSSL_free(buffer); return encoded;
	}
	// ���������� ���������� ������
	catch (...) { OPENSSL_free(buffer); throw; }
}

std::wstring Aladdin::CAPI::OpenSSL::Certificate::KeyOID() const
{$
	// �������� ������������� �����
	ASN1_OBJECT* pObjectIdentifier = ::OBJ_nid2obj(keyNID); char oid[128]; 

	// ���������� ��������� ����� ��������������
	AE_CHECK_OPENSSL(::OBJ_obj2txt(oid, sizeof(oid), pObjectIdentifier, 1)); 

	// ��������� �������������� ���������
	return to_unicode(oid); 
}

Aladdin::CAPI::KeyUsage Aladdin::CAPI::OpenSSL::Certificate::KeyUsage() const
{$
	// �������� ������������ ����������
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// �������� ������ ������������� �����
	uint32_t rawKeyUsage = ::X509_get_key_usage(pCertificateX509);

	// ���������������� ����������
	int keyUsage = CAPI::KeyUsage::None; 

	// ������� ������ ������������� �����
	if (rawKeyUsage & KU_DIGITAL_SIGNATURE) keyUsage |= KeyUsage::DigitalSignature; 
	if (rawKeyUsage & KU_NON_REPUDIATION  ) keyUsage |= KeyUsage::NonRepudiation; 
	if (rawKeyUsage & KU_KEY_ENCIPHERMENT ) keyUsage |= KeyUsage::KeyEncipherment; 
	if (rawKeyUsage & KU_DATA_ENCIPHERMENT) keyUsage |= KeyUsage::DataEncipherment; 
	if (rawKeyUsage & KU_KEY_AGREEMENT    ) keyUsage |= KeyUsage::KeyAgreement; 
	if (rawKeyUsage & KU_KEY_CERT_SIGN    ) keyUsage |= KeyUsage::CertificateSignature; 
	if (rawKeyUsage & KU_CRL_SIGN         ) keyUsage |= KeyUsage::CrlSignature; 
	if (rawKeyUsage & KU_ENCIPHER_ONLY    ) keyUsage |= KeyUsage::EncipherOnly; 
	if (rawKeyUsage & KU_DECIPHER_ONLY    ) keyUsage |= KeyUsage::DecipherOnly; 

	return (CAPI::KeyUsage)keyUsage; 
}
    
std::shared_ptr<Aladdin::CAPI::IDistinctName> 
Aladdin::CAPI::OpenSSL::Certificate::Issuer() const
{$
	// �������� ������������ ����������
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// �������� ��� ��������
	X509_NAME* pName = ::X509_get_issuer_name(pCertificateX509); 

	// ������� ��� ��������
	return std::shared_ptr<CAPI::IDistinctName>(new DistinctName(pName)); 
}

std::shared_ptr<Aladdin::CAPI::IDistinctName> 
Aladdin::CAPI::OpenSSL::Certificate::Subject() const
{$
	// �������� ������������ ����������
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// �������� ��� ��������
	X509_NAME* pName = ::X509_get_subject_name(pCertificateX509); 

	// ������� ��� ��������
	return std::shared_ptr<CAPI::IDistinctName>(new DistinctName(pName)); 
}

int Aladdin::CAPI::OpenSSL::Certificate::Find(
	const STACK_OF(CMS_SignerInfo)* pSignerInfos) const
{$
	// �������� ������������ ����������
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// ��� ���� ���������
	for (int i = 0; i < ::sk_CMS_SignerInfo_num(pSignerInfos); i++) 
	{
		// �������� ���������� ���������� ��������
		CMS_SignerInfo* pSignerInfo = ::sk_CMS_SignerInfo_value(pSignerInfos, i);

		// ������� ���������� ��������
		if (::CMS_SignerInfo_cert_cmp(pSignerInfo, pCertificateX509) == 0) return i; 
	}
	return -1; 
}

int Aladdin::CAPI::OpenSSL::Certificate::Find(
	const STACK_OF(CMS_RecipientInfo)* pRecipientInfos) const
{$
	// �������� ������������ ����������
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// ��� ���� ���������
	for (int i = 0; i < ::sk_CMS_RecipientInfo_num(pRecipientInfos); i++) 
	try {
		// �������� ���������� ���������� ��������
		CMS_RecipientInfo* pRecipientInfo = ::sk_CMS_RecipientInfo_value(pRecipientInfos, i);

		// � ����������� �� ���� ����������
		switch (::CMS_RecipientInfo_type(pRecipientInfo))
		{
		case CMS_RECIPINFO_TRANS:
		{
			// ��������� ������� ������������
			if (::CMS_RecipientInfo_ktri_cert_cmp(
				pRecipientInfo, pCertificateX509) == 0) return i; 
			break; 
		}
		case CMS_RECIPINFO_AGREE:
		{
			// ������� ������ ������������� ������
			const STACK_OF(CMS_RecipientEncryptedKey)* pEncryptedKeys = 
				::CMS_RecipientInfo_kari_get0_reks(pRecipientInfo);

			// ��������� ������� ������������
			if (Find(pEncryptedKeys) >= 0) { return i; } break; 
		}}
	}
	catch (...) {} return -1; 
}

int Aladdin::CAPI::OpenSSL::Certificate::Find(
	const STACK_OF(CMS_RecipientEncryptedKey)* pEncryptedKeys) const
{$
	// �������� ������������ ����������
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// ��� ���� ������������� ������
	for (int i = 0; i < ::sk_CMS_RecipientEncryptedKey_num(pEncryptedKeys); i++) 
	{
		// ������� ���������� ������������� �����
		CMS_RecipientEncryptedKey* pEncryptedKey = ::sk_CMS_RecipientEncryptedKey_value(pEncryptedKeys, i);

		// ��������� ������������ �����������
		if (::CMS_RecipientEncryptedKey_cert_cmp(pEncryptedKey, pCertificateX509) == 0) return i; 
	}
	return -1; 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Certificate::Encrypt(
	const void* pvData, size_t cbData) const
{$
	// ���������������� ����������
	CMS_ContentInfo* pContentInfo = NULL; unsigned char* buffer = NULL;

	// ����������� ������ � �����
	BIO* pInput = ::BIO_new_mem_buf(pvData, (int)cbData); AE_CHECK_OPENSSL(pInput); 
	try {
		// �������� �������� ����������
		ENGINE* pEngine = NULL; const EVP_CIPHER* pCipher = GetCipher(keyNID, &pEngine); 
		try { 
			// ����������� ������ 
			pContentInfo = ::CMS_encrypt(pCertificatesX509, pInput, pCipher, CMS_BINARY);

			// ��������� ���������� ������
			AE_CHECK_OPENSSL(pContentInfo); ::BIO_free(pInput);
			
			// ���������� ���������� �������
			if (pEngine) ::ENGINE_finish(pEngine);
		}
		// ���������� ���������� �������
		catch (...) { if (pEngine) ::ENGINE_finish(pEngine); throw; }
	}
	// ���������� ���������� �����
	catch (...) { ::BIO_free(pInput); throw; } 
	try {
		// ������������ ������������� ������
		int cb = ::i2d_CMS_ContentInfo(pContentInfo, &buffer); 

		// ��������� ���������� ������
		if (cb < 0) AE_CHECK_OPENSSL(0); 
		try { 
			// ����������� �������������� �������������
			std::vector<unsigned char> encoded(buffer, buffer + cb); 

			// ���������� ���������� ������
			::CMS_ContentInfo_free(pContentInfo); 

			// ���������� ���������� �������
			OPENSSL_free(buffer); return encoded;
		}
		// ���������� ���������� �������
		catch (...) { OPENSSL_free(buffer); throw; } 
	}
	// ���������� ���������� �������
	catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }
}
        
std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Certificate::VerifySign(
	const void* pvData, size_t cbData) const
{$
	// ������� ������������ �����
	BIO* pOutput = ::BIO_new(::BIO_s_mem()); AE_CHECK_OPENSSL(pOutput);
	try { 
		// ��������� �������������� ����
		const unsigned char* p = (const unsigned char*)pvData;

		// ������������� CMS-���������
		CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

		// ��������� ���������� ������
		AE_CHECK_OPENSSL(pContentInfo); 
		try { 
			// ������� ������ �������� �������
			unsigned int flags = CMS_BINARY | CMS_NOINTERN | CMS_NO_SIGNER_CERT_VERIFY; 

			// ��������� ������������ �������
			AE_CHECK_OPENSSL(::CMS_verify(pContentInfo, pCertificatesX509, NULL, NULL, pOutput, flags)); 

			// ���������� ���������� ������
			::CMS_ContentInfo_free(pContentInfo); 
		}
		// ���������� ���������� ������
		catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

		// �������� ����� ������
		BUF_MEM* ptr; BIO_get_mem_ptr(pOutput, &ptr);

		// ����������� ������
		std::vector<unsigned char> data(ptr->data, ptr->data + ptr->length); 

		// ���������� ���������� �����
		::BIO_free(pOutput); return data; 
	}
	// ���������� ���������� �����
	catch (...) { ::BIO_free(pOutput); throw; } 
}

///////////////////////////////////////////////////////////////////////////////
// ������ ����
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
void Aladdin::CAPI::OpenSSL::PrivateKey::SetCertificateContext(PCCERT_CONTEXT) const
{$
	// ���������������� ��������
	AE_CHECK_WINAPI(NTE_BAD_KEY); 
}
#endif 

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::PrivateKey::Encrypt(
	const ICertificate* pCertificate, const void* pvData, size_t cbData) const
{$
	// ����������� ������
	return pCertificate->Encrypt(pvData, cbData); 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::PrivateKey::Decrypt(
	const void* pvData, size_t cbData) const
{$
	// ������� ������������ �����
	BIO* pOutput = ::BIO_new(::BIO_s_mem()); AE_CHECK_OPENSSL(pOutput);
	try { 
		// ��������� �������������� ����
		const unsigned char* p = (const unsigned char*)pvData;

		// ������������� CMS-���������
		CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

		// ��������� ���������� ������
		AE_CHECK_OPENSSL(pContentInfo); unsigned int flags = CMS_BINARY; 
		try { 
			// ��������� ������������ �������
			AE_CHECK_OPENSSL(::CMS_decrypt(pContentInfo, 
				GetPrivateKeyObject(), GetCertificateObject(), NULL, pOutput, flags
			)); 
			// ���������� ���������� ������
			::CMS_ContentInfo_free(pContentInfo);
		}
		// ���������� ���������� ������
		catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

		// �������� ����� ������
		BUF_MEM* ptr; BIO_get_mem_ptr(pOutput, &ptr);

		// ����������� ������
		std::vector<unsigned char> data(ptr->data, ptr->data + ptr->length); 

		// ���������� ���������� �����
		::BIO_free(pOutput); return data; 
	}
	// ���������� ���������� �����
	catch (...) { ::BIO_free(pOutput); throw; } 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::PrivateKey::SignData(
	const void* pvData, size_t cbData) const
{$
	// ���������������� ����������
	CMS_ContentInfo* pContentInfo = NULL; unsigned char* buffer = NULL;

	// ����������� ������ � �����
	BIO* pInput = ::BIO_new_mem_buf(pvData, (int)cbData); AE_CHECK_OPENSSL(pInput); 
	try {
		// ������� ������ �������� �������
		unsigned int flags = CMS_BINARY | CMS_NOSMIMECAP; 

		// ��������� ������ 
		pContentInfo = ::CMS_sign(GetCertificateObject(), 
			GetPrivateKeyObject(), NULL, pInput, flags
		);
		// ��������� ���������� ������
		AE_CHECK_OPENSSL(pContentInfo); ::BIO_free(pInput);
	}
	// ���������� ���������� �����
	catch (...) { ::BIO_free(pInput); throw; } 
	try {
		// ������������ ������������� ������
		int cb = ::i2d_CMS_ContentInfo(pContentInfo, &buffer); 

		// ��������� ���������� ������
		if (cb < 0) AE_CHECK_OPENSSL(0); 
		try { 
			// ����������� �������������� �������������
			std::vector<unsigned char> encoded(buffer, buffer + cb); 

			// ���������� ���������� �������
			::CMS_ContentInfo_free(pContentInfo); 

			// ���������� ���������� ������
			OPENSSL_free(buffer); return encoded;
		}
		// ���������� ���������� �������
		catch (...) { OPENSSL_free(buffer); throw; } 
	}
	// ���������� ���������� �������
	catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ������ ���� ���������� PKCS12
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Aladdin::CAPI::OpenSSL::PrivateKey> 
Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::Create(
	const char* szName, const std::vector<unsigned char>& certificate)
{$
	// ��� �������� ����������� �����������
	if (strncmp(szName, "memory:", 7) == 0)
	{
		// ������������� ����������
		std::vector<unsigned char> content = DecodeBase64(szName + 7); 

		// ������� ������������ �����
		BIO* pContent = ::BIO_new_mem_buf(&content[0], (int)content.size()); 

		// ��������� ���������� ������
		AE_CHECK_OPENSSL(pContent);
		try { 
			// ������� ������ ����
			std::shared_ptr<PrivateKey> pPrivateKey(
				new PrivateKeyPKCS12(szName, pContent, certificate) 
			); 
			// ��������� ���������� ������
			::BIO_free(pContent); return pPrivateKey; 
		}
		// ���������� ���������� �������
		catch (...) { ::BIO_free(pContent); throw; } 
	}
	// ��� �������� ����� �����
	else if (strncmp(szName, "file:", 5) == 0)
	{
		// ������� ����
		BIO* pFile = BIO_new_file(szName + 5, "rb"); AE_CHECK_OPENSSL(pFile);
		try { 
			// ������� ������ ����
			std::shared_ptr<PrivateKey> pPrivateKey(
				new PrivateKeyPKCS12(szName, pFile, certificate) 
			); 
			// ��������� ���������� ������
			::BIO_free(pFile); return pPrivateKey; 
		}
		// ���������� ���������� �������
		catch (...) { ::BIO_free(pFile); throw; } 
	}
	// ������ �������� �����
	else return std::shared_ptr<PrivateKey>(); 
}

std::shared_ptr<Aladdin::CAPI::OpenSSL::PrivateKey> 
Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::Decode(
	const void* pvContent, size_t cbContent, const wchar_t* szPassword)
{$
	// ������������ ������ ����
	std::string name = "memory:" + EncodeBase64<char>(pvContent, cbContent); 

	// ������� ������������ �����
	BIO* pContent = ::BIO_new_mem_buf(pvContent, (int)cbContent); 

	// ��������� ���������� ������
	AE_CHECK_OPENSSL(pContent);
	try { 
		// ������� ������ ����
		std::shared_ptr<PrivateKey> pPrivateKey(
			new PrivateKeyPKCS12(name.c_str(), pContent, szPassword) 
		); 
		// ��������� ���������� ������
		::BIO_free(pContent); return pPrivateKey; 
	}
	// ���������� ���������� �������
	catch (...) { ::BIO_free(pContent); throw; } 
}

Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::PrivateKeyPKCS12(
	const char* szName, BIO* pContent, 
	const std::vector<unsigned char>& certificate) : name(szName)
{$
	// ������� ��������� PKCS12
	p12 = ::d2i_PKCS12_bio(pContent, NULL); AE_CHECK_OPENSSL(p12);
	try { 
		// ��� ���������� ������� ������
		if (!::PKCS12_verify_mac(p12, "", 0) && !::PKCS12_verify_mac(p12, NULL, 0))
		{
			// ���������������� ����������
			const unsigned char* p = &certificate[0];

			// ������������� ����������
			pCertificateX509 = ::d2i_X509(NULL, &p, (long)(ptrdiff_t)certificate.size());

			// ��������� ���������� ������
			AE_CHECK_OPENSSL(pCertificateX509); pPrivateKey = NULL; 
		}
		else { SetPassword(L"");

			// ������� ����� �� ����������
			AE_CHECK_OPENSSL(::PKCS12_parse(p12, "", &pPrivateKey, &pCertificateX509, NULL));
		}
	}
	// ���������� ���������� �������
	catch (...) { ::PKCS12_free(p12); throw; }
}

Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::PrivateKeyPKCS12(
	const char* szName, BIO* pContent, const wchar_t* szPassword) : name(szName)
{$
	// ������� ��������� PKCS12
	p12 = ::d2i_PKCS12_bio(pContent, NULL); AE_CHECK_OPENSSL(p12);
	try { 
		// ��������� �������������� ����
		std::string password = from_unicode(szPassword); SetPassword(szPassword);

		// ��������� ������������ ������
		AE_CHECK_OPENSSL(::PKCS12_verify_mac(p12, password.c_str(), (int)password.length())); 

		// ������� ����� �� ����������
		AE_CHECK_OPENSSL(::PKCS12_parse(p12, password.c_str(), &pPrivateKey, &pCertificateX509, NULL));
	}
	// ���������� ���������� �������
	catch (...) { ::PKCS12_free(p12); throw; }
}

Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::~PrivateKeyPKCS12()
{$
	// ���������� ���������� �������
	if (pPrivateKey) ::EVP_PKEY_free(pPrivateKey); 

	// ���������� ���������� �������
	::X509_free(pCertificateX509); ::PKCS12_free(p12);
}

std::wstring Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::ToString() const
{$
	// �������� �������������� ������������� �����������
	std::vector<unsigned char> certificate = Certificate()->Encoded(); 

	// ������������ ���� �����������
	std::string encoded = "pkcs12," + name + "," + EncodeBase64<char>(&certificate[0], certificate.size()); 

	// ��������� �������������� ���������
	return to_unicode(encoded.c_str(), encoded.size());  
}

void Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::Authenticate(const wchar_t* szPassword)
{$
	// ��������� �������������� ���������
	std::string password = from_unicode(szPassword); X509* pCertificate = NULL;

	// ��������� ���������� ������
	if (::PKCS12_verify_mac(p12, password.c_str(), (int)password.size()) <= 0)
	{
		// ���������� ��� ������
		PKCS12err(PKCS12_F_PKCS12_PARSE, PKCS12_R_MAC_VERIFY_FAILURE); AE_CHECK_OPENSSL(0);
	}
	// ������� ����� �� ����������
	AE_CHECK_OPENSSL(::PKCS12_parse(p12, password.c_str(), &pPrivateKey, &pCertificate, NULL));

	// ���������� ���������� �������
	SetPassword(szPassword); ::X509_free(pCertificate);
}

static void Authenticate(const wchar_t*, const wchar_t*, const wchar_t* szPassword, void* pvData)
{
	// ��������� ������ ����������
	((Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12*)pvData)->Authenticate(szPassword); 
}

EVP_PKEY* Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::GetPrivateKeyObject() const
{$ 
	// ������� ������ ����
	if (pPrivateKey) { return pPrivateKey; } std::wstring wname = to_unicode(name.c_str()); 

	// ��������������� ��� ����������
	if (wcsncmp(wname.c_str(), L"memory:", 7) == 0) wname = L"PKCS12 cryptographic container"; 

	// �������� ������ ��������������
	const IPasswordAuthentication* pAuthentication = GetAuthentication(); 

	// ��� ���������� ��������������
	if (!pAuthentication)
	{
		// ���������� ��� ������
		PKCS12err(PKCS12_F_PKCS12_PARSE, PKCS12_R_MAC_VERIFY_FAILURE); 

		// ��������� ����������
		AE_CHECK_OPENSSL(0); return NULL; 
	}
	// �������� ������ ����������
	std::wstring user = pAuthentication->Authenticate(
		wname.c_str(), NULL, SIZE_MAX, 
		::Authenticate, const_cast<PrivateKeyPKCS12*>(this)
	); 
	// ��������� ���������� ������ ��������
	if (user.size() == 0)
	{
		// ���������� ��� ������
		PKCS12err(PKCS12_F_PKCS12_PARSE, PKCS12_R_MAC_VERIFY_FAILURE); 

		// ��������� ����������
		AE_CHECK_OPENSSL(0); return NULL; 
	}
	return pPrivateKey; 
} 

///////////////////////////////////////////////////////////////////////////////
// ������ ���� �������
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::PrivateKeyEngine::PrivateKeyEngine(
	ENGINE* pEngine, const char* keyName, const std::vector<unsigned char>& certificate) 
{$
	// ��������� �������������
	this->pEngine = pEngine; AE_CHECK_OPENSSL(::ENGINE_init(pEngine)); 
	try { 
		// ���������������� ����������
		const unsigned char* p = &certificate[0]; this->keyName = keyName; 

		// ������������� ����������
		pCertificateX509 = ::d2i_X509(NULL, &p, (long)(ptrdiff_t)certificate.size());

		// ��������� ���������� ������
		AE_CHECK_OPENSSL(pCertificateX509); pPrivateKey = NULL;
	}
	// ���������� ���������� �������
	catch (...) { ::ENGINE_finish(pEngine); throw; }
}

Aladdin::CAPI::OpenSSL::PrivateKeyEngine::~PrivateKeyEngine()
{$
	// ���������� ���������� �������
	if (pPrivateKey) ::EVP_PKEY_free(pPrivateKey);  

	// ���������� ���������� �������
	::X509_free(pCertificateX509); ::ENGINE_finish(pEngine);
}

std::wstring Aladdin::CAPI::OpenSSL::PrivateKeyEngine::ToString() const
{$
	// �������� �������������� ������������� �����������
	std::vector<unsigned char> certificate = Certificate()->Encoded(); 

	// ������� ��� �������
	std::string encoded = ::ENGINE_get_id(pEngine); 

	// �������� ��� ����������
	encoded += "," + keyName + "," + EncodeBase64<char>(&certificate[0], certificate.size()); 

	// ��������� �������������� ���������
	return to_unicode(encoded.c_str(), encoded.size());  
}

EVP_PKEY* Aladdin::CAPI::OpenSSL::PrivateKeyEngine::GetPrivateKeyObject() const
{$ 
	// ������� ������ ����
	if (pPrivateKey) return pPrivateKey; 

	// �������� ������ ��������������
	if (const IPasswordAuthentication* pAuthentication = GetAuthentication())
	{
		// ������� ������ �������������� � �������������
		UI_METHOD* pInputMethod = pAuthentication->CreateInputMethod(keyName.c_str()); 
		try { 
			// ��������� ������ ����
			pPrivateKey = ::ENGINE_load_private_key(pEngine, keyName.c_str(), pInputMethod, NULL);

			// ��������� ���������� ������
			AE_CHECK_OPENSSL(pPrivateKey); 
			
			// ���������� ���������� �������
			::UI_destroy_method(pInputMethod); return pPrivateKey; 
		}
		// ���������� ���������� �������
		catch (...) { ::UI_destroy_method(pInputMethod); throw; }
	}
	else {
		// ��������� ������ ����
		pPrivateKey = ::ENGINE_load_private_key(pEngine, keyName.c_str(), NULL, NULL);

		// ��������� ���������� ������
		AE_CHECK_OPENSSL(pPrivateKey); return pPrivateKey; 
	}
} 

///////////////////////////////////////////////////////////////////////////////
// ������ ���� SSL �������
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::PrivateKeySSL::PrivateKeySSL(ENGINE* pEngine)
{$
	// ��������� �������������
	this->pEngine = pEngine; AE_CHECK_OPENSSL(::ENGINE_init(pEngine));
}

Aladdin::CAPI::OpenSSL::PrivateKeySSL::~PrivateKeySSL()
{$
	// ���������� ���������� �������
	if (pCertificateX509) ::X509_free(pCertificateX509); 

	// ���������� ���������� �������
	if (pPrivateKey) { ::EVP_PKEY_free(pPrivateKey); } ::ENGINE_finish(pEngine);
}

std::wstring Aladdin::CAPI::OpenSSL::PrivateKeySSL::ToString() const
{$
	// ������� ��� �������
	std::string encoded = ::ENGINE_get_id(pEngine); encoded += ",openssl"; 

	// ��������� �������������� ���������
	return to_unicode(encoded.c_str(), encoded.size());  
}

X509* Aladdin::CAPI::OpenSSL::PrivateKeySSL::GetCertificateObject() const
{$
	// ��������� ������� �����������
	if (pCertificateX509) { return pCertificateX509; } const char* szTarget = "SSL key container"; 

	// �������� ������ ��������������
	if (const IPasswordAuthentication* pAuthentication = GetAuthentication())
	{
		// ������� ������ �������������� � �������������
		UI_METHOD* pInputMethod = pAuthentication->CreateInputMethod(szTarget); 
		try { 
			// ��������� �������� ���� � ����������
			AE_CHECK_OPENSSL(::ENGINE_load_ssl_client_cert(pEngine, NULL, NULL, 
				&pCertificateX509, &pPrivateKey, NULL, pInputMethod, NULL
			));
			// ���������� ���������� �������
			::UI_destroy_method(pInputMethod); return pCertificateX509; 
		}
		// ���������� ���������� �������
		catch (...) { ::UI_destroy_method(pInputMethod); throw; }
	}
	else {
		// ��������� �������� ���� � ����������
		::ENGINE_load_ssl_client_cert(pEngine, NULL, NULL, 
			&pCertificateX509, &pPrivateKey, NULL, NULL, NULL
		);
		// ������� ����������
		AE_CHECK_OPENSSL(pCertificateX509); return pCertificateX509; 
	}
}

EVP_PKEY* Aladdin::CAPI::OpenSSL::PrivateKeySSL::GetPrivateKeyObject() const
{$
	// ��������� ������� ������� �����
	if (pPrivateKey) { return pPrivateKey; } const char* szTarget = "SSL key container"; 

	// �������� ������ ��������������
	if (const IPasswordAuthentication* pAuthentication = GetAuthentication())
	{
		// ������� ������ �������������� � �������������
		UI_METHOD* pInputMethod = pAuthentication->CreateInputMethod(szTarget); 
		try { 
			// ��������� �������� ���� � ����������
			AE_CHECK_OPENSSL(::ENGINE_load_ssl_client_cert(pEngine, NULL, NULL, 
				&pCertificateX509, &pPrivateKey, NULL, pInputMethod, NULL
			));
			// ���������� ���������� �������
			::UI_destroy_method(pInputMethod); return pPrivateKey; 
		}
		// ���������� ���������� �������
		catch (...) { ::UI_destroy_method(pInputMethod); throw; }
	}
	else {
		// ��������� �������� ���� � ����������
		::ENGINE_load_ssl_client_cert(pEngine, NULL, NULL, 
			&pCertificateX509, &pPrivateKey, NULL, NULL, NULL
		);
		// ������� ������ ����
		AE_CHECK_OPENSSL(pPrivateKey); return pPrivateKey; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::Factory::Factory(ENGINE* pCAPI)
{$
	// �������� ��������� ������
	::ENGINE_up_ref(pCAPI); this->pCAPI = pCAPI; 
	try {
		// ��������� �������������
		AE_CHECK_OPENSSL(::ENGINE_init(pCAPI)); 
	}
	// ���������� ���������� �������
	catch (...) { ::ENGINE_free(pCAPI); throw; }
}

#if defined _WIN32
void Aladdin::CAPI::OpenSSL::Factory::RegisterCAPI(PCWSTR szPath)
{$
	// ��������� ������������� ����
	std::string path = from_unicode(szPath); 

	// ������� ����������� ������
	ENGINE* pEngine = ::ENGINE_by_id("dynamic"); AE_CHECK_OPENSSL(pEngine); 
	try {
		// ������� ���� � ������� CAPI
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd_string(pEngine, "SO_PATH", path.c_str(), 0)); 

		// ������� ���������� � ������
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "LIST_ADD", 1, NULL, NULL, 0)); 

		// ��������� ������
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "LOAD", 0, NULL, NULL, 0)); 

		// ������� ����������� ������
		::ENGINE_free(pEngine); 
	}
	// ���������� ���������� �������
	catch (...) { ::ENGINE_free(pEngine); throw; } 
}

Aladdin::CAPI::OpenSSL::Factory::Factory(PCWSTR szPath)
{$
	// �������� ��������� ������
	pCAPI = ::ENGINE_by_id("capi"); 

	// ���������������� ������
	if (!pCAPI) { RegisterCAPI(szPath); loaded = true; } 

	// �������� ��������� ������
	pCAPI = ::ENGINE_by_id("capi"); AE_CHECK_OPENSSL(pCAPI); 
	try {
		// ��������� �������������
		AE_CHECK_OPENSSL(::ENGINE_init(pCAPI)); 
	}
	// ���������� ���������� �������
	catch (...) { ::ENGINE_free(pCAPI); throw; }
}

Aladdin::CAPI::OpenSSL::Factory::Factory()
{$
	// �������� ��������� ������
	pCAPI = ::ENGINE_by_id("capi"); AE_CHECK_OPENSSL(pCAPI); 
	try {
		// ��������� �������������
		AE_CHECK_OPENSSL(::ENGINE_init(pCAPI)); 
	}
	// ���������� ���������� �������
	catch (...) { ::ENGINE_free(pCAPI); throw; }
}
// ���������� ���������� �������
Aladdin::CAPI::OpenSSL::Factory::~Factory() 
{$ 
	// ���������� ���������� �������
	::ENGINE_finish(pCAPI); ::ENGINE_free(pCAPI); 
}
#else 
Aladdin::CAPI::OpenSSL::Factory:: Factory() {$}
Aladdin::CAPI::OpenSSL::Factory::~Factory() {$}

std::shared_ptr<Aladdin::CAPI::OpenSSL::IPasswordAuthentication> 
Aladdin::CAPI::OpenSSL::Factory::PasswordAuthentication(void* hwnd) const
{$
	// ������� ������ �������������� � �������������� �������
	return std::shared_ptr<IPasswordAuthentication>(
		new WxWidgets::DialogAuthentication(hwnd)
	); 
}
#endif 

void Aladdin::CAPI::OpenSSL::Factory::GenerateRandom(void* pvData, size_t cbData) const
{$
	// ������������� ��������� ������
	AE_CHECK_OPENSSL(::RAND_bytes((unsigned char*)pvData, (int)cbData)); 
}

std::wstring Aladdin::CAPI::OpenSSL::Factory::PasswordAuthenticate(
	void* hwnd, const wchar_t* szTarget, const wchar_t* szUser, 
	size_t attempts, pfnAuthenticate pfnAuthenticate, void* pvData) const
{$
	// �������� ������ ��������������
	std::shared_ptr<IPasswordAuthentication> pAuthentication = PasswordAuthentication(hwnd); 

	// ��������� �������������� ����
	CAPI::OpenSSL::IPasswordAuthentication* pPasswordAuthentication = 
		static_cast<CAPI::OpenSSL::IPasswordAuthentication*>(&*pAuthentication); 

	// ��������� ��������������
	return pPasswordAuthentication->Authenticate(
		szTarget, szUser, attempts, pfnAuthenticate, pvData
	); 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Factory::PasswordEncrypt(
	const wchar_t* szCultureOID, const wchar_t* szPassword, 
	const void* pvData, size_t cbData) const
{$
	// ������� �� �����������
	return std::vector<unsigned char>(); 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Factory::PasswordDecrypt(
	const wchar_t* szPassword, const void* pvData, size_t cbData) const
{$
	// ������������ ������ � ��������� UTF-8
	std::string password = to_utf8(szPassword); 

	// ������� ������������ �����
	BIO* pOutput = ::BIO_new(::BIO_s_mem()); AE_CHECK_OPENSSL(pOutput);
	try { 
		// ��������� �������������� ����
		const unsigned char* p = (const unsigned char*)pvData;

		// ������������� CMS-���������
		CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

		// ��������� ���������� ������
		AE_CHECK_OPENSSL(pContentInfo); unsigned int flags = CMS_BINARY; 
		try { 	
			// ���������� ��� ���������
			const ASN1_OBJECT* pObjectIdentifier = ::CMS_get0_type(pContentInfo);

			// ��� ������������� ������ �� ������������ �����
			if (::OBJ_obj2nid(pObjectIdentifier) == NID_pkcs7_encrypted) 
			{
				// ������������ ������ �� ������������ �����
				AE_CHECK_OPENSSL(::CMS_EncryptedData_decrypt(pContentInfo, 
					(unsigned char*)password.c_str(), password.size(), NULL, pOutput, flags
				));  
			}
			else {
				// ������� ������ 
				AE_CHECK_OPENSSL(::CMS_decrypt_set1_password(
					pContentInfo, (unsigned char*)password.c_str(), password.size()
				)); 
				// ������������ ������ �� ������
				AE_CHECK_OPENSSL(::CMS_decrypt(pContentInfo, NULL, NULL, NULL, pOutput, flags));  
			}
			// ���������� ���������� ������
			::CMS_ContentInfo_free(pContentInfo);
		}
		// ���������� ���������� ������
		catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

		// �������� ����� ������
		BUF_MEM* ptr; BIO_get_mem_ptr(pOutput, &ptr);

		// ����������� ������
		std::vector<unsigned char> data(ptr->data, ptr->data + ptr->length); 

		// ���������� ���������� �����
		::BIO_free(pOutput); return data; 
	}
	// ���������� ���������� �����
	catch (...) { ::BIO_free(pOutput); throw; } 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::OpenSSL::Factory::DecodeCertificate(const void* pvEncoded, size_t cbEncoded) const
{$
	// ������������� ����������
	return Certificate::Decode(pvEncoded, cbEncoded); 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::DecodePrivateKey(const wchar_t* szEncoded, void* hwnd) const
{$
	// ��������� �������������� ���������
	std::string encoded = from_unicode(szEncoded); const char* szEncodedA = encoded.c_str(); 

	// ����� ����������� ����� �����
	const char* szSeparator = strchr(szEncodedA, ','); 

	// ��������� ������� �����������
	if (!szSeparator) return std::shared_ptr<CAPI::IPrivateKey>();

	// ������� ��� �������
	std::string engine(szEncodedA, szSeparator - szEncodedA); 

	// ��� ������������ ������
	if (strcmp(szSeparator + 1, "openssl") == 0) { 

		// ����� ��������� ������
		ENGINE* pEngine = ::ENGINE_by_id(engine.c_str()); AE_CHECK_OPENSSL(pEngine); 
		try { 
			// ������� ������ ������� �����
			std::shared_ptr<PrivateKey> pPrivateKey(new PrivateKeySSL(pEngine)); 

			// ���������� ������ ��������������
			if (hwnd) pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); 

			// ���������� ���������� �������
			::ENGINE_free(pEngine); return pPrivateKey; 
		}
		// ���������� ���������� �������
		catch (...) { ::ENGINE_free(pEngine); throw; }
	}
	else {
		// ����� ����������� �����������
		szSeparator = strrchr(szEncodedA = szSeparator + 1, ','); 

		// ��������� ������� �����������
		if (!szSeparator) return std::shared_ptr<CAPI::IPrivateKey>();

		// ���������� ��� �����
		std::string keyName(szEncodedA, szSeparator - szEncodedA); 

		// ������������� ������ � ��������� Base64
		std::vector<unsigned char> certificate = DecodeBase64(szSeparator + 1); 

		if (engine == "pkcs12")
		{
			// ������������� ������ ���� PKCS12
			std::shared_ptr<PrivateKey> pPrivateKey = 
				PrivateKeyPKCS12::Create(keyName.c_str(), certificate); 

			// ���������� ������ ��������������
			if (hwnd) pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); 
			
			return pPrivateKey;
		}
#if defined _WIN32
		// ��������� ������ �����
		else if (strncmp(engine.c_str(), "capi:", 5) == 0)
		{
			// ������������� ������ ���� CAPI
			std::shared_ptr<PrivateKey> pPrivateKey = 
				DecodePrivateKey_CAPI(engine.c_str(), keyName.c_str(), certificate); 

			// ���������� ������ ��������������
			if (hwnd) pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); 
			
			return pPrivateKey;
		}
#endif 
		else {
			// ����� ��������� ������
			ENGINE* pEngine = ::ENGINE_by_id(engine.c_str()); AE_CHECK_OPENSSL(pEngine); 
			try { 
				// ������� ������ ������� �����
				std::shared_ptr<PrivateKey> pPrivateKey(
					new PrivateKeyEngine(pEngine, keyName.c_str(), certificate)
				); 
				// ���������� ������ ��������������
				if (hwnd) pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); 

				// ���������� ���������� �������
				::ENGINE_free(pEngine); return pPrivateKey;
			}
			// ���������� ���������� �������
			catch (...) { ::ENGINE_free(pEngine); throw; }
		}
	}
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::DecodePKCS12(
	const void* pvEncoded, size_t cbEncoded, const wchar_t* szPassword) const
{$
	// ������������� ��������� PKCS12
	return PrivateKeyPKCS12::Decode(pvEncoded, cbEncoded, szPassword); 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::OpenSSL::Factory::FindVerifyCertificate(
	const void* pvData, size_t cbData, 
    const std::vector<unsigned char>* pEncodedCertificates, size_t cCertificates) const
{$
	// ������� ������ ������������
	std::vector<std::shared_ptr<Certificate>> certificates(cCertificates); 

	// ��� ���� ������ ������
	for (size_t i = 0; i < cCertificates; i++)
	try {
		// ������� ������ �����������
		certificates[i] = Certificate::Decode(&pEncodedCertificates[i][0], pEncodedCertificates[i].size()); 
	}
	// ��������� �������������� ����
	catch (...) {} const unsigned char* p = (const unsigned char*)pvData;

	// ������������� CMS-���������
	CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

	// ��������� ���������� ������
	AE_CHECK_OPENSSL(pContentInfo); size_t index = (size_t)(-1);
	try { 	
		// ���������� ��� ���������
		const ASN1_OBJECT* pObjectIdentifier = ::CMS_get0_type(pContentInfo);

		// ��������� ��� ���������
		if (::OBJ_obj2nid(pObjectIdentifier) == NID_pkcs7_signed) 
		{
			// �������� ���������� ������� ��������
			const STACK_OF(CMS_SignerInfo)* pSignerInfos = ::CMS_get0_SignerInfos(pContentInfo);

			// ��� ���� ������������
			for (size_t i = 0; i < certificates.size(); i++)
			{
				// ��������� ���������� ������ �����������
				if (!certificates[i]) continue; 

				// ����� ������� ������������
				if (certificates[i]->Find(pSignerInfos) >= 0) { index = i; break; }
			}
		}
		// ���������� ���������� ������
		::CMS_ContentInfo_free(pContentInfo); 
	}
	// ���������� ���������� ������
	catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

	// ������� ��������� ����������
	return (index != (size_t)(-1)) ? certificates[index] : std::shared_ptr<Certificate>(); 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::FindDecryptPrivateKey(
	const void* pvData, size_t cbData, void* hwnd, 
    const std::wstring* pEncodedPrivateKeys, size_t cPrivateKeys) const
{$
	// ������� ������ ������������
	std::vector<std::shared_ptr<Certificate>> certificates(cPrivateKeys); 

	// ��� ���� ������ ������
	for (size_t i = 0; i < cPrivateKeys; i++)
	try {
		// ������������� ������ ����
		std::shared_ptr<CAPI::IPrivateKey> privateKey = DecodePrivateKey(pEncodedPrivateKeys[i].c_str(), nullptr); 

		// ������������ ����������
		std::vector<unsigned char> encodedCertificate = privateKey->Certificate()->Encoded(); 

		// ������� ������ �����������
		certificates[i] = Certificate::Decode(&encodedCertificate[0], encodedCertificate.size()); 
	}
	// ��������� �������������� ����
	catch (...) {} const unsigned char* p = (const unsigned char*)pvData;

	// ������������� CMS-���������
	CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

	// ��������� ���������� ������
	AE_CHECK_OPENSSL(pContentInfo); size_t index = (size_t)(-1); 
	try { 
		// ���������� ��� ���������
		const ASN1_OBJECT* pObjectIdentifier = ::CMS_get0_type(pContentInfo);

		// ��������� ��� ���������
		if (::OBJ_obj2nid(pObjectIdentifier) == NID_pkcs7_enveloped)
		{
			// �������� ���������� ������� ��������
			const STACK_OF(CMS_RecipientInfo)* pRecipientInfos = ::CMS_get0_RecipientInfos(pContentInfo);

			// ��� ���� ������������
			for (size_t i = 0; i < certificates.size(); i++)
			{
				// ��������� ���������� ������ �����������
				if (!certificates[i]) continue; 

				// ����� ������� ������������
				if (certificates[i]->Find(pRecipientInfos) >= 0) { index = i; break; }
			}
		}
		// ���������� ���������� ������
		::CMS_ContentInfo_free(pContentInfo); 
	}
	// ���������� ���������� ������
	catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

	// ������������ �� �������
	if (index == (size_t)(-1)) return std::shared_ptr<CAPI::IPrivateKey>(); 

	// ������������� ��������������� ������ ����
	return DecodePrivateKey(pEncodedPrivateKeys[index].c_str(), hwnd); 
}

#if defined _WIN32
std::vector<std::wstring> Aladdin::CAPI::OpenSSL::Factory::EnumeratePrivateKeys(
	void*, bool systemOnly) const
{$
	// ����������� ����� CryptoAPI
	return EnumeratePrivateKeys_CAPI(KeyUsage::None, systemOnly);
}
std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::SelectPrivateKeySSL(void* hwnd) const
{$
	// ������� ������ ���� SSL
	return SelectPrivateKeySSL_CAPI((HWND)hwnd); 
}
#else 
std::vector<std::wstring> 
Aladdin::CAPI::OpenSSL::Factory::EnumeratePrivateKeys(void* hwnd, bool) const
{$
	// ������ ������ ������
	std::vector<std::wstring> privateKeys;

	// ��� ���� ������������� ��������
	for (ENGINE* pEngine = ::ENGINE_get_first(); pEngine; pEngine = ::ENGINE_get_next(pEngine))
	{
		// ��������� ������� ����������� ������ ����������� SSL
		if (!::ENGINE_get_ssl_client_cert_function(pEngine)) continue;  

		// ������� ��� �������
		std::string encoded = ::ENGINE_get_id(pEngine); encoded += ",openssl"; 

		// ��������� �������������� ���������
		privateKeys.push_back(to_unicode(encoded.c_str(), encoded.size()));  
	}
	return privateKeys;
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::SelectPrivateKeySSL(void* hwnd) const
{$
	// ��� ���� ������������� ��������
	for (ENGINE* pEngine = ::ENGINE_get_first(); pEngine; pEngine = ::ENGINE_get_next(pEngine))
	{
		// ��������� ������� ����������� ������ ����������� SSL
		if (!::ENGINE_get_ssl_client_cert_function(pEngine)) continue;  

		// ������� ������ ������� �����
		std::shared_ptr<PrivateKey> pPrivateKey(new PrivateKeySSL(pEngine)); 

		// ���������� ������ ��������������
		pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); return pPrivateKey; 
	}
	// ������� ������ ������
	return std::shared_ptr<CAPI::IPrivateKey>(); 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������� ������� ����������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Aladdin::CAPI::IFactory> Aladdin::CAPI::OpenSSL::CreateFactory()
{$
	// ������� ������� ����������
	return std::shared_ptr<CAPI::IFactory>(new Factory()); 
}
#if defined _WIN32
std::shared_ptr<Aladdin::CAPI::IFactory> 
Aladdin::CAPI::OpenSSL::CreateFactory(const wchar_t* szPath) 
{$
	// ������� ������� ����������
	if (!szPath) return std::shared_ptr<CAPI::IFactory>(new Factory());

	// ������� ������� ����������
	return std::shared_ptr<CAPI::IFactory>(new Factory(szPath)); 
}
#endif 

