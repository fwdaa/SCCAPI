#include "stdafx.h"
#include "CertificateStore.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "CertificateStore.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// Хранилище сертификатов
//////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::CertificateStore(
	String^ provider, String^ name, DWORD location)
{$
	// определить имя хранилища
	pin_ptr<CONST WCHAR> szName = PtrToStringChars(name); 

	// преобразовать кодировку
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(provider); 

	// выделить буфер требуемого размера
	std::string strProvider(encoded->Length + 1, 0); 

	// скопировать имя провайдера
	Marshal::Copy(encoded, 0, IntPtr(&strProvider[0]), encoded->Length); 

	// открыть хранилище заданного типа
	hCertStore = ::CertOpenStore(
		strProvider.c_str(), X509_ASN_ENCODING, 0, location, szName
	); 
	// проверить отсутствие ошибок
	AE_CHECK_WINAPI(hCertStore != nullptr); 
}

Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::~CertificateStore() 
{$
	// освободить описатель хранилища
	::CertCloseStore(hCertStore, 0); 
}

array<BYTE>^ Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::Find(
	PCERT_PUBLIC_KEY_INFO pInfo)
{$
	// найти сертификат в хранилище
	PCCERT_CONTEXT hCertContext = ::CertFindCertificateInStore(hCertStore, 
		X509_ASN_ENCODING, 0, CERT_FIND_PUBLIC_KEY, pInfo, 0
	); 
	// проверить наличие сертификата
	if (hCertContext == 0) return nullptr; 
	try {
		// выделить буфер для сертификата
		array<BYTE>^ certificate = gcnew array<BYTE>(hCertContext->cbCertEncoded); 

		// скопировать содержимое сертификата
		Marshal::Copy(IntPtr(hCertContext->pbCertEncoded), certificate, 0, certificate->Length); 

		// вернуть содержимое сертификата
		return certificate; 
	}
	// закрыть контекст сертификата
	finally { ::CertFreeCertificateContext(hCertContext); }
}

array<BYTE>^ Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::Find(
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	// получить закодированный ключ
	array<BYTE>^ encoded = publicKeyInfo->Encoded; DWORD cbInfo = 0; 

	// получить адрес буфера
	pin_ptr<BYTE> ptrEncoded = &encoded[0]; DWORD cbEncoded = encoded->Length;
	
	// определить требуемый размер памяти
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
		ptrEncoded, cbEncoded, CRYPT_DECODE_NOCOPY_FLAG, 0, &cbInfo
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> vecInfo(cbInfo); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&vecInfo[0]; 

	// раскодировать открытый ключ
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
		ptrEncoded, cbEncoded, CRYPT_DECODE_NOCOPY_FLAG, pInfo, &cbInfo
	)); 
	// найти сертификат в хранилище
	return Find(pInfo); 
}

void Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::Write(array<BYTE>^ certificate)
{$
	// получить адрес сертификата
	pin_ptr<BYTE> ptrCertificate = &certificate[0]; 

	// создать контекст сертификата
	PCCERT_CONTEXT hCertContext = ::CertCreateCertificateContext(
		X509_ASN_ENCODING, ptrCertificate, certificate->Length
	); 
	// проверить отсутствие ошибок
	AE_CHECK_WINAPI(hCertContext != 0);
	try {
		// добавить сертификат в хранилище
		AE_CHECK_WINAPI(::CertAddCertificateContextToStore(
			hCertStore, hCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0
		)); 
	}
	// закрыть контекст сертификата
	finally { ::CertFreeCertificateContext(hCertContext);  }
}
