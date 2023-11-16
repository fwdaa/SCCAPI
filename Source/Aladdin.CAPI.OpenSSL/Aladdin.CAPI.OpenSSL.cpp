#include "pch.h"
#include "ui.h"
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#include "TraceWindows.h"
#include "TraceOpenSSL.h"
#ifdef WPP_CONTROL_GUIDS
#include "Aladdin.CAPI.OpenSSL.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Кодировка Base-64
///////////////////////////////////////////////////////////////////////////////
template <>
std::string Aladdin::CAPI::OpenSSL::EncodeBase64<char>(const void* pvData, size_t cbData)
{$
	// выделить буфер требуемого размера
	std::string encoded((cbData + 2) / 3 * 4, 0); unsigned char encodedBlock[66]; 

	// для всех блоков по 48-байтов
	size_t i; for (i = 0; cbData >= 48; cbData -= 48, i++)
	{
		// закодировать часть данных
		::EVP_EncodeBlock(encodedBlock, (unsigned char*)pvData, 48); 

		// скопировать закодированные данные
		memcpy(&encoded[i * 64], encodedBlock, 64); 

		// перейти на следующий блок данных
		pvData = (const unsigned char*)pvData + 48; 
	}
	if (cbData > 0)
	{
		// закодировать часть данных
		::EVP_EncodeBlock(encodedBlock, (unsigned char*)pvData, (int)cbData); 

		// скопировать закодированные данные
		memcpy(&encoded[i * 64], encodedBlock, (cbData + 2) / 3 * 4);
	}
	return encoded; 
}

template <>
std::wstring Aladdin::CAPI::OpenSSL::EncodeBase64<wchar_t>(const void* pvData, size_t cbData)
{$
	// закодировать данные в кодировку Base-64
	std::string encoded = EncodeBase64<char>(pvData, cbData); 

	// выполнить преобразование кодировки
	return to_unicode(encoded.c_str(), encoded.size()); 
}
// инстанцирование функции
template std::wstring Aladdin::CAPI::OpenSSL::EncodeBase64<wchar_t>(const void*, size_t); 

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::DecodeBase64(const char* szEncoded, size_t cch)
{$
	// определить размер строки
	if (cch == (size_t)(-1)) { cch = strlen(szEncoded); } unsigned char decodedBlock[48];

	// выделить буфер требуемого размера
	std::vector<unsigned char> decoded((cch + 3) / 4 * 3, 0); 

	// для всех блоков по 64-байта
	size_t i; for (i = 0; cch >= 64; cch -= 64, i++, szEncoded += 64)
	{
		// раскодировать блок данных
		int cb = ::EVP_DecodeBlock(decodedBlock, (const unsigned char*)szEncoded, 64); 

		// проверить отсутствие ошибок
		if (cb < 0) { AE_CHECK_OPENSSL(0); }

		// скопировать раскодированные данные
		memcpy(&decoded[i * 48], decodedBlock, 48); 
	}
	if (cch != 0) 
	{  
		// раскодировать блок данных
		int cb = ::EVP_DecodeBlock(decodedBlock, (const unsigned char*)szEncoded, (int)cch); 

		// проверить отсутствие ошибок
		if (cb < 0) { AE_CHECK_OPENSSL(0); }

		// скопировать раскодированные данные
		memcpy(&decoded[i * 48], decodedBlock, cb); 

		// удалить дополнение
		if (cch >= 2 && szEncoded[cch - 2] == '=') decoded.resize(decoded.size() - 2); else 
		if (cch >= 1 && szEncoded[cch - 1] == '=') decoded.resize(decoded.size() - 1);
	}
	return decoded; 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::DecodeBase64(const wchar_t* szEncoded, size_t cch)
{$
	// выполнить преобразование кодировки
	std::string encoded = from_unicode(szEncoded, cch); 

	// раскодировать данные из кодировки Base-64
	return DecodeBase64(encoded.c_str(), encoded.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// Используемый алгоритм шифрования
///////////////////////////////////////////////////////////////////////////////
static const EVP_CIPHER* GetCipher(int keyNID, ENGINE** ppEngine)
{$
	// для ключей GOST
	if (keyNID == NID_id_GostR3410_94       || keyNID == NID_id_GostR3410_2001     || 
	    keyNID == NID_id_GostR3410_2012_256 || keyNID == NID_id_GostR3410_2012_512)
	{
		// получить плагин для алгоритма
		*ppEngine = ::ENGINE_get_cipher_engine(NID_id_Gost28147_89); 

		// проверить наличие плагина
		if (!*ppEngine) AE_CHECK_OPENSSL(0); 
		try {
			// получить алгоритм
			const EVP_CIPHER* pCipher = ::ENGINE_get_cipher(
				*ppEngine, NID_id_Gost28147_89
			); 
			// проверить наличие алгоритма
			if (!pCipher) AE_CHECK_OPENSSL(0); return pCipher;
		}
		// освободить выделенные ресурсы
		catch (...) { ::ENGINE_finish(*ppEngine); throw; }
	}
	// для ключей ECC-256
	if (keyNID == NID_X9_62_prime256v1 ||
	    keyNID == NID_X9_62_c2pnb272w1 || 
	    keyNID == NID_X9_62_c2pnb304w1 ||
	    keyNID == NID_X9_62_c2tnb359v1 || 
	    keyNID == NID_X9_62_c2pnb368w1 ||  
	    keyNID == NID_secp256k1        ||
	    keyNID == NID_sect283r1		   || 
	    keyNID == NID_sect283k1 	    )
	{ 
		// создать алгоритм AES-CBC
		*ppEngine = NULL; return ::EVP_aes_128_cbc(); 
	}
	// для ключей ECC-384
	if (keyNID == NID_X9_62_c2tnb431r1	|| 
	    keyNID == NID_secp384r1			|| 
	    keyNID == NID_sect409k1			|| 
	    keyNID == NID_sect409r1			 ) 
	{ 
		// создать алгоритм AES-CBC
		*ppEngine = NULL; return ::EVP_aes_192_cbc(); 
	}
	// для ключей ECC-512
	if (keyNID == NID_secp521r1 || 
	    keyNID == NID_sect571k1 || 
	    keyNID == NID_sect571r1) 
	{ 
		// создать алгоритм AES-CBC
		*ppEngine = NULL; return ::EVP_aes_256_cbc(); 
	}
	// создать алгоритм TDES-CBC
	*ppEngine = NULL; return ::EVP_des_ede3_cbc(); 
}

///////////////////////////////////////////////////////////////////////////////
// Отличимое имя
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::DistinctName::DistinctName(X509_NAME* pName)
{$
	// адрес выделенного буфера
	unsigned char* bufferEncoded = NULL;

	// закодировать имя издателя 
	int cb = ::i2d_X509_NAME(pName, &bufferEncoded); 

	// проверить отсутствие ошибок
	if (cb < 0) AE_CHECK_OPENSSL(0); 
	try {
		// скопировать закодированное представление
		encoded = std::vector<unsigned char>(
			bufferEncoded, bufferEncoded + cb
		); 
		// освободить выделенную память
		OPENSSL_free(bufferEncoded); 
	}
	// освободить выделенную память
	catch (...) { OPENSSL_free(bufferEncoded); throw; }

	// получить строковое представление имени
	char* bufferName = ::X509_NAME_oneline(pName, NULL, 0);

	// проверить отсутствие ошибок
	AE_CHECK_OPENSSL(bufferName); 
	try { 
		// сохранить строковое представление имени
		name = to_unicode(bufferName); 

		// освободить выделенную память
		OPENSSL_free(bufferName); 
	}
	// освободить выделенную память
	catch (...) { OPENSSL_free(bufferName); throw; }
}
// деструктор
Aladdin::CAPI::OpenSSL::DistinctName::~DistinctName() {$}

///////////////////////////////////////////////////////////////////////////////
// Сертификат открытого ключа
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Aladdin::CAPI::OpenSSL::Certificate> 
Aladdin::CAPI::OpenSSL::Certificate::Decode(const void* pvEncoded, size_t cbEncoded) 
{$ 
	// выполнить преобразование типа
	const unsigned char* p = (const unsigned char*)pvEncoded;

	// раскодировать сертификат
	X509* pCertificateX509 = ::d2i_X509(NULL, &p, (long)(ptrdiff_t)cbEncoded);

	// проверить отсутствие ошибок
	AE_CHECK_OPENSSL(pCertificateX509); 
	try { 
		// создать объект сертификата
		std::shared_ptr<CAPI::OpenSSL::Certificate> pCertificate(
			new Certificate(pCertificateX509)
		); 
		// освободить выделенную память 
		::X509_free(pCertificateX509); return pCertificate; 
	}
	// освободить выделенную память 
	catch (...) { ::X509_free(pCertificateX509); throw; }
}

Aladdin::CAPI::OpenSSL::Certificate::Certificate(X509* pCertificateX509) 
{$ 
	// получить открытый ключ сертификата
	X509_PUBKEY* pPublicKey = ::X509_get_X509_PUBKEY(pCertificateX509); 

	// инициализировать переменные
	ASN1_OBJECT* pObjectIdentifier = NULL; 

	// извлечь параметры открытого ключа
	::X509_PUBKEY_get0_param(&pObjectIdentifier, NULL, NULL, NULL, pPublicKey); 

	// получить значение идентификатора открытого ключа
	keyNID = ::OBJ_obj2nid(pObjectIdentifier);

	// проверить отсутствие ошибок
	if (keyNID == NID_undef) AE_CHECK_OPENSSL(0); 

	// увеличить счетчик ссылок
	AE_CHECK_OPENSSL(::X509_up_ref(pCertificateX509)); 
	try { 
		// создать список сертификатов
		pCertificatesX509 = ::sk_X509_new_reserve(NULL, 1);  

		// проверить отсутствие ошибок
		AE_CHECK_OPENSSL(pCertificatesX509); 
	
		// добавить сертификат в список
		::sk_X509_push(pCertificatesX509, pCertificateX509);
	}
	// освободить выделенную память 
	catch (...) { ::X509_free(pCertificateX509); throw; }
}

Aladdin::CAPI::OpenSSL::Certificate::~Certificate() 
{$
	// освободить выделенную память
	::sk_X509_pop_free(pCertificatesX509, ::X509_free); 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Certificate::Encoded() const
{$
	// получить используемый сертификат
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// адрес выделенного буфера
	unsigned char* buffer = NULL;

	// закодировать сертификат 
	int cb = ::i2d_X509(pCertificateX509, &buffer); 

	// проверить отсутствие ошибок
	if (cb < 0) AE_CHECK_OPENSSL(0); 
	try {
		// скопировать закодированное представление
		std::vector<unsigned char> encoded(buffer, buffer + cb); 

		// освободить выделенную память
		OPENSSL_free(buffer); return encoded;
	}
	// освободить выделенную память
	catch (...) { OPENSSL_free(buffer); throw; }
}

std::wstring Aladdin::CAPI::OpenSSL::Certificate::KeyOID() const
{$
	// получить идентификатор ключа
	ASN1_OBJECT* pObjectIdentifier = ::OBJ_nid2obj(keyNID); char oid[128]; 

	// определить строковую форму идентификатора
	AE_CHECK_OPENSSL(::OBJ_obj2txt(oid, sizeof(oid), pObjectIdentifier, 1)); 

	// выполнить преобразование кодировки
	return to_unicode(oid); 
}

Aladdin::CAPI::KeyUsage Aladdin::CAPI::OpenSSL::Certificate::KeyUsage() const
{$
	// получить используемый сертификат
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// получить способ использования ключа
	uint32_t rawKeyUsage = ::X509_get_key_usage(pCertificateX509);

	// инициализировать переменную
	int keyUsage = CAPI::KeyUsage::None; 

	// указать способ использования ключа
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
	// получить используемый сертификат
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// получить имя издателя
	X509_NAME* pName = ::X509_get_issuer_name(pCertificateX509); 

	// вернуть имя издателя
	return std::shared_ptr<CAPI::IDistinctName>(new DistinctName(pName)); 
}

std::shared_ptr<Aladdin::CAPI::IDistinctName> 
Aladdin::CAPI::OpenSSL::Certificate::Subject() const
{$
	// получить используемый сертификат
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// получить имя субъекта
	X509_NAME* pName = ::X509_get_subject_name(pCertificateX509); 

	// вернуть имя субъекта
	return std::shared_ptr<CAPI::IDistinctName>(new DistinctName(pName)); 
}

int Aladdin::CAPI::OpenSSL::Certificate::Find(
	const STACK_OF(CMS_SignerInfo)* pSignerInfos) const
{$
	// получить используемый сертификат
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// для всех субъектов
	for (int i = 0; i < ::sk_CMS_SignerInfo_num(pSignerInfos); i++) 
	{
		// получить информацию отдельного субъекта
		CMS_SignerInfo* pSignerInfo = ::sk_CMS_SignerInfo_value(pSignerInfos, i);

		// извлечь сертификат субъекта
		if (::CMS_SignerInfo_cert_cmp(pSignerInfo, pCertificateX509) == 0) return i; 
	}
	return -1; 
}

int Aladdin::CAPI::OpenSSL::Certificate::Find(
	const STACK_OF(CMS_RecipientInfo)* pRecipientInfos) const
{$
	// получить используемый сертификат
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// для всех субъектов
	for (int i = 0; i < ::sk_CMS_RecipientInfo_num(pRecipientInfos); i++) 
	try {
		// получить информацию отдельного субъекта
		CMS_RecipientInfo* pRecipientInfo = ::sk_CMS_RecipientInfo_value(pRecipientInfos, i);

		// в зависимости от типа информации
		switch (::CMS_RecipientInfo_type(pRecipientInfo))
		{
		case CMS_RECIPINFO_TRANS:
		{
			// проверить наличие соответствия
			if (::CMS_RecipientInfo_ktri_cert_cmp(
				pRecipientInfo, pCertificateX509) == 0) return i; 
			break; 
		}
		case CMS_RECIPINFO_AGREE:
		{
			// извлечь данные зашифрованных ключей
			const STACK_OF(CMS_RecipientEncryptedKey)* pEncryptedKeys = 
				::CMS_RecipientInfo_kari_get0_reks(pRecipientInfo);

			// проверить наличие соответствия
			if (Find(pEncryptedKeys) >= 0) { return i; } break; 
		}}
	}
	catch (...) {} return -1; 
}

int Aladdin::CAPI::OpenSSL::Certificate::Find(
	const STACK_OF(CMS_RecipientEncryptedKey)* pEncryptedKeys) const
{$
	// получить используемый сертификат
	X509* pCertificateX509 = ::sk_X509_value(pCertificatesX509, 0); 

	// для всех зашифрованных ключей
	for (int i = 0; i < ::sk_CMS_RecipientEncryptedKey_num(pEncryptedKeys); i++) 
	{
		// извлечь информацию зашированного ключа
		CMS_RecipientEncryptedKey* pEncryptedKey = ::sk_CMS_RecipientEncryptedKey_value(pEncryptedKeys, i);

		// проверить соответствие сертификата
		if (::CMS_RecipientEncryptedKey_cert_cmp(pEncryptedKey, pCertificateX509) == 0) return i; 
	}
	return -1; 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Certificate::Encrypt(
	const void* pvData, size_t cbData) const
{$
	// инициализировать переменные
	CMS_ContentInfo* pContentInfo = NULL; unsigned char* buffer = NULL;

	// скопировать данные в буфер
	BIO* pInput = ::BIO_new_mem_buf(pvData, (int)cbData); AE_CHECK_OPENSSL(pInput); 
	try {
		// получить алгоритм шифрования
		ENGINE* pEngine = NULL; const EVP_CIPHER* pCipher = GetCipher(keyNID, &pEngine); 
		try { 
			// зашифровать данные 
			pContentInfo = ::CMS_encrypt(pCertificatesX509, pInput, pCipher, CMS_BINARY);

			// проверить отсутствие ошибок
			AE_CHECK_OPENSSL(pContentInfo); ::BIO_free(pInput);
			
			// освободить выделенные ресурсы
			if (pEngine) ::ENGINE_finish(pEngine);
		}
		// освободить выделенные ресурсы
		catch (...) { if (pEngine) ::ENGINE_finish(pEngine); throw; }
	}
	// освободить выделенный буфер
	catch (...) { ::BIO_free(pInput); throw; } 
	try {
		// закодировать зашифрованные данные
		int cb = ::i2d_CMS_ContentInfo(pContentInfo, &buffer); 

		// проверить отсутствие ошибок
		if (cb < 0) AE_CHECK_OPENSSL(0); 
		try { 
			// скопировать закодированное представление
			std::vector<unsigned char> encoded(buffer, buffer + cb); 

			// освободить выделенную память
			::CMS_ContentInfo_free(pContentInfo); 

			// освободить выделенные ресурсы
			OPENSSL_free(buffer); return encoded;
		}
		// освободить выделенные ресурсы
		catch (...) { OPENSSL_free(buffer); throw; } 
	}
	// освободить выделенные ресурсы
	catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }
}
        
std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Certificate::VerifySign(
	const void* pvData, size_t cbData) const
{$
	// создать динамический буфер
	BIO* pOutput = ::BIO_new(::BIO_s_mem()); AE_CHECK_OPENSSL(pOutput);
	try { 
		// выполнить преобразование типа
		const unsigned char* p = (const unsigned char*)pvData;

		// раскодировать CMS-структуру
		CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

		// проверить отсутствие ошибок
		AE_CHECK_OPENSSL(pContentInfo); 
		try { 
			// указать способ проверки подписи
			unsigned int flags = CMS_BINARY | CMS_NOINTERN | CMS_NO_SIGNER_CERT_VERIFY; 

			// проверить корректность подписи
			AE_CHECK_OPENSSL(::CMS_verify(pContentInfo, pCertificatesX509, NULL, NULL, pOutput, flags)); 

			// освободить выделенную память
			::CMS_ContentInfo_free(pContentInfo); 
		}
		// освободить выделенную память
		catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

		// получить адрес данных
		BUF_MEM* ptr; BIO_get_mem_ptr(pOutput, &ptr);

		// скопировать данные
		std::vector<unsigned char> data(ptr->data, ptr->data + ptr->length); 

		// освободить выделенный буфер
		::BIO_free(pOutput); return data; 
	}
	// освободить выделенный буфер
	catch (...) { ::BIO_free(pOutput); throw; } 
}

///////////////////////////////////////////////////////////////////////////////
// Личный ключ
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
void Aladdin::CAPI::OpenSSL::PrivateKey::SetCertificateContext(PCCERT_CONTEXT) const
{$
	// неподдерживаемая операция
	AE_CHECK_WINAPI(NTE_BAD_KEY); 
}
#endif 

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::PrivateKey::Encrypt(
	const ICertificate* pCertificate, const void* pvData, size_t cbData) const
{$
	// зашифровать данные
	return pCertificate->Encrypt(pvData, cbData); 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::PrivateKey::Decrypt(
	const void* pvData, size_t cbData) const
{$
	// создать динамический буфер
	BIO* pOutput = ::BIO_new(::BIO_s_mem()); AE_CHECK_OPENSSL(pOutput);
	try { 
		// выполнить преобразование типа
		const unsigned char* p = (const unsigned char*)pvData;

		// раскодировать CMS-структуру
		CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

		// проверить отсутствие ошибок
		AE_CHECK_OPENSSL(pContentInfo); unsigned int flags = CMS_BINARY; 
		try { 
			// проверить корректность подписи
			AE_CHECK_OPENSSL(::CMS_decrypt(pContentInfo, 
				GetPrivateKeyObject(), GetCertificateObject(), NULL, pOutput, flags
			)); 
			// освободить выделенную память
			::CMS_ContentInfo_free(pContentInfo);
		}
		// освободить выделенную память
		catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

		// получить адрес данных
		BUF_MEM* ptr; BIO_get_mem_ptr(pOutput, &ptr);

		// скопировать данные
		std::vector<unsigned char> data(ptr->data, ptr->data + ptr->length); 

		// освободить выделенный буфер
		::BIO_free(pOutput); return data; 
	}
	// освободить выделенный буфер
	catch (...) { ::BIO_free(pOutput); throw; } 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::PrivateKey::SignData(
	const void* pvData, size_t cbData) const
{$
	// инициализировать переменные
	CMS_ContentInfo* pContentInfo = NULL; unsigned char* buffer = NULL;

	// скопировать данные в буфер
	BIO* pInput = ::BIO_new_mem_buf(pvData, (int)cbData); AE_CHECK_OPENSSL(pInput); 
	try {
		// указать способ проверки подписи
		unsigned int flags = CMS_BINARY | CMS_NOSMIMECAP; 

		// подписать данные 
		pContentInfo = ::CMS_sign(GetCertificateObject(), 
			GetPrivateKeyObject(), NULL, pInput, flags
		);
		// проверить отсутствие ошибок
		AE_CHECK_OPENSSL(pContentInfo); ::BIO_free(pInput);
	}
	// освободить выделенный буфер
	catch (...) { ::BIO_free(pInput); throw; } 
	try {
		// закодировать зашифрованные данные
		int cb = ::i2d_CMS_ContentInfo(pContentInfo, &buffer); 

		// проверить отсутствие ошибок
		if (cb < 0) AE_CHECK_OPENSSL(0); 
		try { 
			// скопировать закодированное представление
			std::vector<unsigned char> encoded(buffer, buffer + cb); 

			// освободить выделенные ресурсы
			::CMS_ContentInfo_free(pContentInfo); 

			// освободить выделенную память
			OPENSSL_free(buffer); return encoded;
		}
		// освободить выделенные ресурсы
		catch (...) { OPENSSL_free(buffer); throw; } 
	}
	// освободить выделенные ресурсы
	catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Личный ключ контейнера PKCS12
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Aladdin::CAPI::OpenSSL::PrivateKey> 
Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::Create(
	const char* szName, const std::vector<unsigned char>& certificate)
{$
	// при указании содержимого коентейнера
	if (strncmp(szName, "memory:", 7) == 0)
	{
		// раскодировать содержимое
		std::vector<unsigned char> content = DecodeBase64(szName + 7); 

		// создать динамический буфер
		BIO* pContent = ::BIO_new_mem_buf(&content[0], (int)content.size()); 

		// проверить отсутствие ошибок
		AE_CHECK_OPENSSL(pContent);
		try { 
			// создать личный ключ
			std::shared_ptr<PrivateKey> pPrivateKey(
				new PrivateKeyPKCS12(szName, pContent, certificate) 
			); 
			// проверить отсутствие ошибок
			::BIO_free(pContent); return pPrivateKey; 
		}
		// освободить выделенные ресурсы
		catch (...) { ::BIO_free(pContent); throw; } 
	}
	// при указании имени файла
	else if (strncmp(szName, "file:", 5) == 0)
	{
		// открыть файл
		BIO* pFile = BIO_new_file(szName + 5, "rb"); AE_CHECK_OPENSSL(pFile);
		try { 
			// создать личный ключ
			std::shared_ptr<PrivateKey> pPrivateKey(
				new PrivateKeyPKCS12(szName, pFile, certificate) 
			); 
			// проверить отсутствие ошибок
			::BIO_free(pFile); return pPrivateKey; 
		}
		// освободить выделенные ресурсы
		catch (...) { ::BIO_free(pFile); throw; } 
	}
	// ошибка создания ключа
	else return std::shared_ptr<PrivateKey>(); 
}

std::shared_ptr<Aladdin::CAPI::OpenSSL::PrivateKey> 
Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::Decode(
	const void* pvContent, size_t cbContent, const wchar_t* szPassword)
{$
	// закодировать личный ключ
	std::string name = "memory:" + EncodeBase64<char>(pvContent, cbContent); 

	// создать динамический буфер
	BIO* pContent = ::BIO_new_mem_buf(pvContent, (int)cbContent); 

	// проверить отсутствие ошибок
	AE_CHECK_OPENSSL(pContent);
	try { 
		// создать личный ключ
		std::shared_ptr<PrivateKey> pPrivateKey(
			new PrivateKeyPKCS12(name.c_str(), pContent, szPassword) 
		); 
		// проверить отсутствие ошибок
		::BIO_free(pContent); return pPrivateKey; 
	}
	// освободить выделенные ресурсы
	catch (...) { ::BIO_free(pContent); throw; } 
}

Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::PrivateKeyPKCS12(
	const char* szName, BIO* pContent, 
	const std::vector<unsigned char>& certificate) : name(szName)
{$
	// открыть контейнер PKCS12
	p12 = ::d2i_PKCS12_bio(pContent, NULL); AE_CHECK_OPENSSL(p12);
	try { 
		// при отсутствии пустого пароля
		if (!::PKCS12_verify_mac(p12, "", 0) && !::PKCS12_verify_mac(p12, NULL, 0))
		{
			// инициализировать переменную
			const unsigned char* p = &certificate[0];

			// раскодировать сертификат
			pCertificateX509 = ::d2i_X509(NULL, &p, (long)(ptrdiff_t)certificate.size());

			// проверить отсутствие ошибок
			AE_CHECK_OPENSSL(pCertificateX509); pPrivateKey = NULL; 
		}
		else { SetPassword(L"");

			// извлечь ключи из контейнера
			AE_CHECK_OPENSSL(::PKCS12_parse(p12, "", &pPrivateKey, &pCertificateX509, NULL));
		}
	}
	// освободить выделенные ресурсы
	catch (...) { ::PKCS12_free(p12); throw; }
}

Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::PrivateKeyPKCS12(
	const char* szName, BIO* pContent, const wchar_t* szPassword) : name(szName)
{$
	// открыть контейнер PKCS12
	p12 = ::d2i_PKCS12_bio(pContent, NULL); AE_CHECK_OPENSSL(p12);
	try { 
		// выполнить преобразование типа
		std::string password = from_unicode(szPassword); SetPassword(szPassword);

		// проверить корректность пароля
		AE_CHECK_OPENSSL(::PKCS12_verify_mac(p12, password.c_str(), (int)password.length())); 

		// извлечь ключи из контейнера
		AE_CHECK_OPENSSL(::PKCS12_parse(p12, password.c_str(), &pPrivateKey, &pCertificateX509, NULL));
	}
	// освободить выделенные ресурсы
	catch (...) { ::PKCS12_free(p12); throw; }
}

Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::~PrivateKeyPKCS12()
{$
	// освободить выделенные ресурсы
	if (pPrivateKey) ::EVP_PKEY_free(pPrivateKey); 

	// освободить выделенные ресурсы
	::X509_free(pCertificateX509); ::PKCS12_free(p12);
}

std::wstring Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::ToString() const
{$
	// получить закодированное представление сертификата
	std::vector<unsigned char> certificate = Certificate()->Encoded(); 

	// закодировать ключ конетейнера
	std::string encoded = "pkcs12," + name + "," + EncodeBase64<char>(&certificate[0], certificate.size()); 

	// выполнить преобразование кодировки
	return to_unicode(encoded.c_str(), encoded.size());  
}

void Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::Authenticate(const wchar_t* szPassword)
{$
	// выполнить преобразование кодировки
	std::string password = from_unicode(szPassword); X509* pCertificate = NULL;

	// проверить совпадение пароля
	if (::PKCS12_verify_mac(p12, password.c_str(), (int)password.size()) <= 0)
	{
		// установить код ошибки
		PKCS12err(PKCS12_F_PKCS12_PARSE, PKCS12_R_MAC_VERIFY_FAILURE); AE_CHECK_OPENSSL(0);
	}
	// извлечь ключи из контейнера
	AE_CHECK_OPENSSL(::PKCS12_parse(p12, password.c_str(), &pPrivateKey, &pCertificate, NULL));

	// освободить выделенные ресурсы
	SetPassword(szPassword); ::X509_free(pCertificate);
}

static void Authenticate(const wchar_t*, const wchar_t*, const wchar_t* szPassword, void* pvData)
{
	// проверить пароль контейнера
	((Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12*)pvData)->Authenticate(szPassword); 
}

EVP_PKEY* Aladdin::CAPI::OpenSSL::PrivateKeyPKCS12::GetPrivateKeyObject() const
{$ 
	// вернуть личный ключ
	if (pPrivateKey) { return pPrivateKey; } std::wstring wname = to_unicode(name.c_str()); 

	// скорректировать имя контейнера
	if (wcsncmp(wname.c_str(), L"memory:", 7) == 0) wname = L"PKCS12 cryptographic container"; 

	// получить способ аутентификации
	const IPasswordAuthentication* pAuthentication = GetAuthentication(); 

	// при отсутствии аутентификации
	if (!pAuthentication)
	{
		// установить код ошибки
		PKCS12err(PKCS12_F_PKCS12_PARSE, PKCS12_R_MAC_VERIFY_FAILURE); 

		// выбросить исключение
		AE_CHECK_OPENSSL(0); return NULL; 
	}
	// получить пароль контейнера
	std::wstring user = pAuthentication->Authenticate(
		wname.c_str(), NULL, SIZE_MAX, 
		::Authenticate, const_cast<PrivateKeyPKCS12*>(this)
	); 
	// проверить отсутствие отмены операции
	if (user.size() == 0)
	{
		// установить код ошибки
		PKCS12err(PKCS12_F_PKCS12_PARSE, PKCS12_R_MAC_VERIFY_FAILURE); 

		// выбросить исключение
		AE_CHECK_OPENSSL(0); return NULL; 
	}
	return pPrivateKey; 
} 

///////////////////////////////////////////////////////////////////////////////
// Личный ключ плагина
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::PrivateKeyEngine::PrivateKeyEngine(
	ENGINE* pEngine, const char* keyName, const std::vector<unsigned char>& certificate) 
{$
	// выполнить инициализацию
	this->pEngine = pEngine; AE_CHECK_OPENSSL(::ENGINE_init(pEngine)); 
	try { 
		// инициализировать переменную
		const unsigned char* p = &certificate[0]; this->keyName = keyName; 

		// раскодировать сертификат
		pCertificateX509 = ::d2i_X509(NULL, &p, (long)(ptrdiff_t)certificate.size());

		// проверить отсутствие ошибок
		AE_CHECK_OPENSSL(pCertificateX509); pPrivateKey = NULL;
	}
	// освободить выделенные ресурсы
	catch (...) { ::ENGINE_finish(pEngine); throw; }
}

Aladdin::CAPI::OpenSSL::PrivateKeyEngine::~PrivateKeyEngine()
{$
	// освободить выделенные ресурсы
	if (pPrivateKey) ::EVP_PKEY_free(pPrivateKey);  

	// освободить выделенные ресурсы
	::X509_free(pCertificateX509); ::ENGINE_finish(pEngine);
}

std::wstring Aladdin::CAPI::OpenSSL::PrivateKeyEngine::ToString() const
{$
	// получить закодированное представление сертификата
	std::vector<unsigned char> certificate = Certificate()->Encoded(); 

	// указать имя плагина
	std::string encoded = ::ENGINE_get_id(pEngine); 

	// добавить имя контейнера
	encoded += "," + keyName + "," + EncodeBase64<char>(&certificate[0], certificate.size()); 

	// выполнить преобразование кодировки
	return to_unicode(encoded.c_str(), encoded.size());  
}

EVP_PKEY* Aladdin::CAPI::OpenSSL::PrivateKeyEngine::GetPrivateKeyObject() const
{$ 
	// вернуть личный ключ
	if (pPrivateKey) return pPrivateKey; 

	// получить способ аутентификации
	if (const IPasswordAuthentication* pAuthentication = GetAuthentication())
	{
		// указать способ взаимодействия с пользователем
		UI_METHOD* pInputMethod = pAuthentication->CreateInputMethod(keyName.c_str()); 
		try { 
			// загрузить личный ключ
			pPrivateKey = ::ENGINE_load_private_key(pEngine, keyName.c_str(), pInputMethod, NULL);

			// проверить отсутствие ошибок
			AE_CHECK_OPENSSL(pPrivateKey); 
			
			// освободить выделенные ресурсы
			::UI_destroy_method(pInputMethod); return pPrivateKey; 
		}
		// освободить выделенные ресурсы
		catch (...) { ::UI_destroy_method(pInputMethod); throw; }
	}
	else {
		// загрузить личный ключ
		pPrivateKey = ::ENGINE_load_private_key(pEngine, keyName.c_str(), NULL, NULL);

		// проверить отсутствие ошибок
		AE_CHECK_OPENSSL(pPrivateKey); return pPrivateKey; 
	}
} 

///////////////////////////////////////////////////////////////////////////////
// Личный ключ SSL плагина
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::PrivateKeySSL::PrivateKeySSL(ENGINE* pEngine)
{$
	// выполнить инициализацию
	this->pEngine = pEngine; AE_CHECK_OPENSSL(::ENGINE_init(pEngine));
}

Aladdin::CAPI::OpenSSL::PrivateKeySSL::~PrivateKeySSL()
{$
	// освободить выделенные ресурсы
	if (pCertificateX509) ::X509_free(pCertificateX509); 

	// освободить выделенные ресурсы
	if (pPrivateKey) { ::EVP_PKEY_free(pPrivateKey); } ::ENGINE_finish(pEngine);
}

std::wstring Aladdin::CAPI::OpenSSL::PrivateKeySSL::ToString() const
{$
	// указать имя плагина
	std::string encoded = ::ENGINE_get_id(pEngine); encoded += ",openssl"; 

	// выполнить преобразование кодировки
	return to_unicode(encoded.c_str(), encoded.size());  
}

X509* Aladdin::CAPI::OpenSSL::PrivateKeySSL::GetCertificateObject() const
{$
	// проверить наличие сертификата
	if (pCertificateX509) { return pCertificateX509; } const char* szTarget = "SSL key container"; 

	// получить способ аутентификации
	if (const IPasswordAuthentication* pAuthentication = GetAuthentication())
	{
		// указать способ взаимодействия с пользователем
		UI_METHOD* pInputMethod = pAuthentication->CreateInputMethod(szTarget); 
		try { 
			// загрузить открытый ключ и сертификат
			AE_CHECK_OPENSSL(::ENGINE_load_ssl_client_cert(pEngine, NULL, NULL, 
				&pCertificateX509, &pPrivateKey, NULL, pInputMethod, NULL
			));
			// освободить выделенные ресурсы
			::UI_destroy_method(pInputMethod); return pCertificateX509; 
		}
		// освободить выделенные ресурсы
		catch (...) { ::UI_destroy_method(pInputMethod); throw; }
	}
	else {
		// загрузить открытый ключ и сертификат
		::ENGINE_load_ssl_client_cert(pEngine, NULL, NULL, 
			&pCertificateX509, &pPrivateKey, NULL, NULL, NULL
		);
		// вернуть сертификат
		AE_CHECK_OPENSSL(pCertificateX509); return pCertificateX509; 
	}
}

EVP_PKEY* Aladdin::CAPI::OpenSSL::PrivateKeySSL::GetPrivateKeyObject() const
{$
	// проверить наличие личного ключа
	if (pPrivateKey) { return pPrivateKey; } const char* szTarget = "SSL key container"; 

	// получить способ аутентификации
	if (const IPasswordAuthentication* pAuthentication = GetAuthentication())
	{
		// указать способ взаимодействия с пользователем
		UI_METHOD* pInputMethod = pAuthentication->CreateInputMethod(szTarget); 
		try { 
			// загрузить открытый ключ и сертификат
			AE_CHECK_OPENSSL(::ENGINE_load_ssl_client_cert(pEngine, NULL, NULL, 
				&pCertificateX509, &pPrivateKey, NULL, pInputMethod, NULL
			));
			// освободить выделенные ресурсы
			::UI_destroy_method(pInputMethod); return pPrivateKey; 
		}
		// освободить выделенные ресурсы
		catch (...) { ::UI_destroy_method(pInputMethod); throw; }
	}
	else {
		// загрузить открытый ключ и сертификат
		::ENGINE_load_ssl_client_cert(pEngine, NULL, NULL, 
			&pCertificateX509, &pPrivateKey, NULL, NULL, NULL
		);
		// вернуть личный ключ
		AE_CHECK_OPENSSL(pPrivateKey); return pPrivateKey; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::Factory::Factory(ENGINE* pCAPI)
{$
	// получить требуемый плагин
	::ENGINE_up_ref(pCAPI); this->pCAPI = pCAPI; 
	try {
		// выполнить инициализацию
		AE_CHECK_OPENSSL(::ENGINE_init(pCAPI)); 
	}
	// освободить выделенные ресурсы
	catch (...) { ::ENGINE_free(pCAPI); throw; }
}

#if defined _WIN32
void Aladdin::CAPI::OpenSSL::Factory::RegisterCAPI(PCWSTR szPath)
{$
	// выполнить преобрзование типа
	std::string path = from_unicode(szPath); 

	// создать загрузочный плагин
	ENGINE* pEngine = ::ENGINE_by_id("dynamic"); AE_CHECK_OPENSSL(pEngine); 
	try {
		// указать путь к плагину CAPI
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd_string(pEngine, "SO_PATH", path.c_str(), 0)); 

		// указать добавление в список
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "LIST_ADD", 1, NULL, NULL, 0)); 

		// загрузить плагин
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "LOAD", 0, NULL, NULL, 0)); 

		// удалить загрузочный плагин
		::ENGINE_free(pEngine); 
	}
	// освободить выделенные ресурсы
	catch (...) { ::ENGINE_free(pEngine); throw; } 
}

Aladdin::CAPI::OpenSSL::Factory::Factory(PCWSTR szPath)
{$
	// получить требуемый плагин
	pCAPI = ::ENGINE_by_id("capi"); 

	// зарегистрировать плагин
	if (!pCAPI) { RegisterCAPI(szPath); loaded = true; } 

	// получить требуемый плагин
	pCAPI = ::ENGINE_by_id("capi"); AE_CHECK_OPENSSL(pCAPI); 
	try {
		// выполнить инициализацию
		AE_CHECK_OPENSSL(::ENGINE_init(pCAPI)); 
	}
	// освободить выделенные ресурсы
	catch (...) { ::ENGINE_free(pCAPI); throw; }
}

Aladdin::CAPI::OpenSSL::Factory::Factory()
{$
	// получить требуемый плагин
	pCAPI = ::ENGINE_by_id("capi"); AE_CHECK_OPENSSL(pCAPI); 
	try {
		// выполнить инициализацию
		AE_CHECK_OPENSSL(::ENGINE_init(pCAPI)); 
	}
	// освободить выделенные ресурсы
	catch (...) { ::ENGINE_free(pCAPI); throw; }
}
// освободить выделенные ресурсы
Aladdin::CAPI::OpenSSL::Factory::~Factory() 
{$ 
	// освободить выделенные ресурсы
	::ENGINE_finish(pCAPI); ::ENGINE_free(pCAPI); 
}
#else 
Aladdin::CAPI::OpenSSL::Factory:: Factory() {$}
Aladdin::CAPI::OpenSSL::Factory::~Factory() {$}

std::shared_ptr<Aladdin::CAPI::OpenSSL::IPasswordAuthentication> 
Aladdin::CAPI::OpenSSL::Factory::PasswordAuthentication(void* hwnd) const
{$
	// указать способ аутентификации с использованием диалога
	return std::shared_ptr<IPasswordAuthentication>(
		new WxWidgets::DialogAuthentication(hwnd)
	); 
}
#endif 

void Aladdin::CAPI::OpenSSL::Factory::GenerateRandom(void* pvData, size_t cbData) const
{$
	// сгенерировать случайные данные
	AE_CHECK_OPENSSL(::RAND_bytes((unsigned char*)pvData, (int)cbData)); 
}

std::wstring Aladdin::CAPI::OpenSSL::Factory::PasswordAuthenticate(
	void* hwnd, const wchar_t* szTarget, const wchar_t* szUser, 
	size_t attempts, pfnAuthenticate pfnAuthenticate, void* pvData) const
{$
	// получить способ аутентификации
	std::shared_ptr<IPasswordAuthentication> pAuthentication = PasswordAuthentication(hwnd); 

	// выполнить преобразование типа
	CAPI::OpenSSL::IPasswordAuthentication* pPasswordAuthentication = 
		static_cast<CAPI::OpenSSL::IPasswordAuthentication*>(&*pAuthentication); 

	// выполнить аутентификацию
	return pPasswordAuthentication->Authenticate(
		szTarget, szUser, attempts, pfnAuthenticate, pvData
	); 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Factory::PasswordEncrypt(
	const wchar_t* szCultureOID, const wchar_t* szPassword, 
	const void* pvData, size_t cbData) const
{$
	// функция не реализована
	return std::vector<unsigned char>(); 
}

std::vector<unsigned char> Aladdin::CAPI::OpenSSL::Factory::PasswordDecrypt(
	const wchar_t* szPassword, const void* pvData, size_t cbData) const
{$
	// закодировать пароль в кодировке UTF-8
	std::string password = to_utf8(szPassword); 

	// создать динамический буфер
	BIO* pOutput = ::BIO_new(::BIO_s_mem()); AE_CHECK_OPENSSL(pOutput);
	try { 
		// выполнить преобразование типа
		const unsigned char* p = (const unsigned char*)pvData;

		// раскодировать CMS-структуру
		CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

		// проверить отсутствие ошибок
		AE_CHECK_OPENSSL(pContentInfo); unsigned int flags = CMS_BINARY; 
		try { 	
			// определить тип структуры
			const ASN1_OBJECT* pObjectIdentifier = ::CMS_get0_type(pContentInfo);

			// для зашифрованных данных на симметричном ключе
			if (::OBJ_obj2nid(pObjectIdentifier) == NID_pkcs7_encrypted) 
			{
				// расшифровать данные на симметричном ключе
				AE_CHECK_OPENSSL(::CMS_EncryptedData_decrypt(pContentInfo, 
					(unsigned char*)password.c_str(), password.size(), NULL, pOutput, flags
				));  
			}
			else {
				// указать пароль 
				AE_CHECK_OPENSSL(::CMS_decrypt_set1_password(
					pContentInfo, (unsigned char*)password.c_str(), password.size()
				)); 
				// расшифровать данные на пароле
				AE_CHECK_OPENSSL(::CMS_decrypt(pContentInfo, NULL, NULL, NULL, pOutput, flags));  
			}
			// освободить выделенную память
			::CMS_ContentInfo_free(pContentInfo);
		}
		// освободить выделенную память
		catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

		// получить адрес данных
		BUF_MEM* ptr; BIO_get_mem_ptr(pOutput, &ptr);

		// скопировать данные
		std::vector<unsigned char> data(ptr->data, ptr->data + ptr->length); 

		// освободить выделенный буфер
		::BIO_free(pOutput); return data; 
	}
	// освободить выделенный буфер
	catch (...) { ::BIO_free(pOutput); throw; } 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::OpenSSL::Factory::DecodeCertificate(const void* pvEncoded, size_t cbEncoded) const
{$
	// раскодировать сертификат
	return Certificate::Decode(pvEncoded, cbEncoded); 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::DecodePrivateKey(const wchar_t* szEncoded, void* hwnd) const
{$
	// выполнить преобразование кодировки
	std::string encoded = from_unicode(szEncoded); const char* szEncodedA = encoded.c_str(); 

	// найти разделитель имени ключа
	const char* szSeparator = strchr(szEncodedA, ','); 

	// проверить наличие разделителя
	if (!szSeparator) return std::shared_ptr<CAPI::IPrivateKey>();

	// извлечь имя плагина
	std::string engine(szEncodedA, szSeparator - szEncodedA); 

	// для специального случая
	if (strcmp(szSeparator + 1, "openssl") == 0) { 

		// найти требуемый плагин
		ENGINE* pEngine = ::ENGINE_by_id(engine.c_str()); AE_CHECK_OPENSSL(pEngine); 
		try { 
			// создать объект личного ключа
			std::shared_ptr<PrivateKey> pPrivateKey(new PrivateKeySSL(pEngine)); 

			// установить способ аутентификации
			if (hwnd) pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); 

			// освободить выделенные ресурсы
			::ENGINE_free(pEngine); return pPrivateKey; 
		}
		// освободить выделенные ресурсы
		catch (...) { ::ENGINE_free(pEngine); throw; }
	}
	else {
		// найти разделитель сертификата
		szSeparator = strrchr(szEncodedA = szSeparator + 1, ','); 

		// проверить наличие разделителя
		if (!szSeparator) return std::shared_ptr<CAPI::IPrivateKey>();

		// определить имя ключа
		std::string keyName(szEncodedA, szSeparator - szEncodedA); 

		// раскодировать данные в кодировке Base64
		std::vector<unsigned char> certificate = DecodeBase64(szSeparator + 1); 

		if (engine == "pkcs12")
		{
			// раскодировать личный ключ PKCS12
			std::shared_ptr<PrivateKey> pPrivateKey = 
				PrivateKeyPKCS12::Create(keyName.c_str(), certificate); 

			// установить способ аутентификации
			if (hwnd) pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); 
			
			return pPrivateKey;
		}
#if defined _WIN32
		// проверить формат имени
		else if (strncmp(engine.c_str(), "capi:", 5) == 0)
		{
			// раскодировать личный ключ CAPI
			std::shared_ptr<PrivateKey> pPrivateKey = 
				DecodePrivateKey_CAPI(engine.c_str(), keyName.c_str(), certificate); 

			// установить способ аутентификации
			if (hwnd) pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); 
			
			return pPrivateKey;
		}
#endif 
		else {
			// найти требуемый плагин
			ENGINE* pEngine = ::ENGINE_by_id(engine.c_str()); AE_CHECK_OPENSSL(pEngine); 
			try { 
				// создать объект личного ключа
				std::shared_ptr<PrivateKey> pPrivateKey(
					new PrivateKeyEngine(pEngine, keyName.c_str(), certificate)
				); 
				// установить способ аутентификации
				if (hwnd) pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); 

				// освободить выделенные ресурсы
				::ENGINE_free(pEngine); return pPrivateKey;
			}
			// освободить выделенные ресурсы
			catch (...) { ::ENGINE_free(pEngine); throw; }
		}
	}
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::DecodePKCS12(
	const void* pvEncoded, size_t cbEncoded, const wchar_t* szPassword) const
{$
	// раскодировать контейнер PKCS12
	return PrivateKeyPKCS12::Decode(pvEncoded, cbEncoded, szPassword); 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::OpenSSL::Factory::FindVerifyCertificate(
	const void* pvData, size_t cbData, 
    const std::vector<unsigned char>* pEncodedCertificates, size_t cCertificates) const
{$
	// создать список сертификатов
	std::vector<std::shared_ptr<Certificate>> certificates(cCertificates); 

	// для всех личных ключей
	for (size_t i = 0; i < cCertificates; i++)
	try {
		// создать объект сертификата
		certificates[i] = Certificate::Decode(&pEncodedCertificates[i][0], pEncodedCertificates[i].size()); 
	}
	// выполнить преобразование типа
	catch (...) {} const unsigned char* p = (const unsigned char*)pvData;

	// раскодировать CMS-структуру
	CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

	// проверить отсутствие ошибок
	AE_CHECK_OPENSSL(pContentInfo); size_t index = (size_t)(-1);
	try { 	
		// определить тип структуры
		const ASN1_OBJECT* pObjectIdentifier = ::CMS_get0_type(pContentInfo);

		// проверить тип структуры
		if (::OBJ_obj2nid(pObjectIdentifier) == NID_pkcs7_signed) 
		{
			// получить информацию каждого субъекта
			const STACK_OF(CMS_SignerInfo)* pSignerInfos = ::CMS_get0_SignerInfos(pContentInfo);

			// для всех сертификатов
			for (size_t i = 0; i < certificates.size(); i++)
			{
				// проверить отсутствие ошибок кодирования
				if (!certificates[i]) continue; 

				// найти наличие соответствия
				if (certificates[i]->Find(pSignerInfos) >= 0) { index = i; break; }
			}
		}
		// освободить выделенную память
		::CMS_ContentInfo_free(pContentInfo); 
	}
	// освободить выделенную память
	catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

	// вернуть найденный сертификат
	return (index != (size_t)(-1)) ? certificates[index] : std::shared_ptr<Certificate>(); 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::FindDecryptPrivateKey(
	const void* pvData, size_t cbData, void* hwnd, 
    const std::wstring* pEncodedPrivateKeys, size_t cPrivateKeys) const
{$
	// создать список сертификатов
	std::vector<std::shared_ptr<Certificate>> certificates(cPrivateKeys); 

	// для всех личных ключей
	for (size_t i = 0; i < cPrivateKeys; i++)
	try {
		// раскодировать личный ключ
		std::shared_ptr<CAPI::IPrivateKey> privateKey = DecodePrivateKey(pEncodedPrivateKeys[i].c_str(), nullptr); 

		// закодировать сертификат
		std::vector<unsigned char> encodedCertificate = privateKey->Certificate()->Encoded(); 

		// создать объект сертификата
		certificates[i] = Certificate::Decode(&encodedCertificate[0], encodedCertificate.size()); 
	}
	// выполнить преобразование типа
	catch (...) {} const unsigned char* p = (const unsigned char*)pvData;

	// раскодировать CMS-структуру
	CMS_ContentInfo* pContentInfo = ::d2i_CMS_ContentInfo(NULL, &p, (long)(ptrdiff_t)cbData);

	// проверить отсутствие ошибок
	AE_CHECK_OPENSSL(pContentInfo); size_t index = (size_t)(-1); 
	try { 
		// определить тип структуры
		const ASN1_OBJECT* pObjectIdentifier = ::CMS_get0_type(pContentInfo);

		// проверить тип структуры
		if (::OBJ_obj2nid(pObjectIdentifier) == NID_pkcs7_enveloped)
		{
			// получить информацию каждого субъекта
			const STACK_OF(CMS_RecipientInfo)* pRecipientInfos = ::CMS_get0_RecipientInfos(pContentInfo);

			// для всех сертификатов
			for (size_t i = 0; i < certificates.size(); i++)
			{
				// проверить отсутствие ошибок кодирования
				if (!certificates[i]) continue; 

				// найти наличие соответствия
				if (certificates[i]->Find(pRecipientInfos) >= 0) { index = i; break; }
			}
		}
		// освободить выделенную память
		::CMS_ContentInfo_free(pContentInfo); 
	}
	// освободить выделенную память
	catch (...) { ::CMS_ContentInfo_free(pContentInfo); throw; }

	// соответствие не найдено
	if (index == (size_t)(-1)) return std::shared_ptr<CAPI::IPrivateKey>(); 

	// раскодировать соответствующий личный ключ
	return DecodePrivateKey(pEncodedPrivateKeys[index].c_str(), hwnd); 
}

#if defined _WIN32
std::vector<std::wstring> Aladdin::CAPI::OpenSSL::Factory::EnumeratePrivateKeys(
	void*, bool systemOnly) const
{$
	// перечислить ключи CryptoAPI
	return EnumeratePrivateKeys_CAPI(KeyUsage::None, systemOnly);
}
std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::SelectPrivateKeySSL(void* hwnd) const
{$
	// выбрать личный ключ SSL
	return SelectPrivateKeySSL_CAPI((HWND)hwnd); 
}
#else 
std::vector<std::wstring> 
Aladdin::CAPI::OpenSSL::Factory::EnumeratePrivateKeys(void* hwnd, bool) const
{$
	// список личных ключей
	std::vector<std::wstring> privateKeys;

	// для всех установленных плагинов
	for (ENGINE* pEngine = ::ENGINE_get_first(); pEngine; pEngine = ::ENGINE_get_next(pEngine))
	{
		// проверить наличие возможности выбора сертификата SSL
		if (!::ENGINE_get_ssl_client_cert_function(pEngine)) continue;  

		// указать имя плагина
		std::string encoded = ::ENGINE_get_id(pEngine); encoded += ",openssl"; 

		// выполнить преобразование кодировки
		privateKeys.push_back(to_unicode(encoded.c_str(), encoded.size()));  
	}
	return privateKeys;
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::SelectPrivateKeySSL(void* hwnd) const
{$
	// для всех установленных плагинов
	for (ENGINE* pEngine = ::ENGINE_get_first(); pEngine; pEngine = ::ENGINE_get_next(pEngine))
	{
		// проверить наличие возможности выбора сертификата SSL
		if (!::ENGINE_get_ssl_client_cert_function(pEngine)) continue;  

		// создать объект личного ключа
		std::shared_ptr<PrivateKey> pPrivateKey(new PrivateKeySSL(pEngine)); 

		// установить способ аутентификации
		pPrivateKey->SetAuthentication(PasswordAuthentication(hwnd)); return pPrivateKey; 
	}
	// вернуть список ключей
	return std::shared_ptr<CAPI::IPrivateKey>(); 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Создать фабрику алгоритмов
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Aladdin::CAPI::IFactory> Aladdin::CAPI::OpenSSL::CreateFactory()
{$
	// создать фабрику алгоритмов
	return std::shared_ptr<CAPI::IFactory>(new Factory()); 
}
#if defined _WIN32
std::shared_ptr<Aladdin::CAPI::IFactory> 
Aladdin::CAPI::OpenSSL::CreateFactory(const wchar_t* szPath) 
{$
	// создать фабрику алгоритмов
	if (!szPath) return std::shared_ptr<CAPI::IFactory>(new Factory());

	// создать фабрику алгоритмов
	return std::shared_ptr<CAPI::IFactory>(new Factory(szPath)); 
}
#endif 

