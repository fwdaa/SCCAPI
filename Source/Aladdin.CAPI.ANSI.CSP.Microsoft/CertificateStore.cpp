#include "stdafx.h"
#include "CertificateStore.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "CertificateStore.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// ��������� ������������
//////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::CertificateStore(
	String^ provider, String^ name, DWORD location)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szName = PtrToStringChars(name); 

	// ������������� ���������
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(provider); 

	// �������� ����� ���������� �������
	std::string strProvider(encoded->Length + 1, 0); 

	// ����������� ��� ����������
	Marshal::Copy(encoded, 0, IntPtr(&strProvider[0]), encoded->Length); 

	// ������� ��������� ��������� ����
	hCertStore = ::CertOpenStore(
		strProvider.c_str(), X509_ASN_ENCODING, 0, location, szName
	); 
	// ��������� ���������� ������
	AE_CHECK_WINAPI(hCertStore != nullptr); 
}

Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::~CertificateStore() 
{$
	// ���������� ��������� ���������
	::CertCloseStore(hCertStore, 0); 
}

array<BYTE>^ Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::Find(
	PCERT_PUBLIC_KEY_INFO pInfo)
{$
	// ����� ���������� � ���������
	PCCERT_CONTEXT hCertContext = ::CertFindCertificateInStore(hCertStore, 
		X509_ASN_ENCODING, 0, CERT_FIND_PUBLIC_KEY, pInfo, 0
	); 
	// ��������� ������� �����������
	if (hCertContext == 0) return nullptr; 
	try {
		// �������� ����� ��� �����������
		array<BYTE>^ certificate = gcnew array<BYTE>(hCertContext->cbCertEncoded); 

		// ����������� ���������� �����������
		Marshal::Copy(IntPtr(hCertContext->pbCertEncoded), certificate, 0, certificate->Length); 

		// ������� ���������� �����������
		return certificate; 
	}
	// ������� �������� �����������
	finally { ::CertFreeCertificateContext(hCertContext); }
}

array<BYTE>^ Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::Find(
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	// �������� �������������� ����
	array<BYTE>^ encoded = publicKeyInfo->Encoded; DWORD cbInfo = 0; 

	// �������� ����� ������
	pin_ptr<BYTE> ptrEncoded = &encoded[0]; DWORD cbEncoded = encoded->Length;
	
	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
		ptrEncoded, cbEncoded, CRYPT_DECODE_NOCOPY_FLAG, 0, &cbInfo
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> vecInfo(cbInfo); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&vecInfo[0]; 

	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
		ptrEncoded, cbEncoded, CRYPT_DECODE_NOCOPY_FLAG, pInfo, &cbInfo
	)); 
	// ����� ���������� � ���������
	return Find(pInfo); 
}

void Aladdin::CAPI::ANSI::CSP::Microsoft::CertificateStore::Write(array<BYTE>^ certificate)
{$
	// �������� ����� �����������
	pin_ptr<BYTE> ptrCertificate = &certificate[0]; 

	// ������� �������� �����������
	PCCERT_CONTEXT hCertContext = ::CertCreateCertificateContext(
		X509_ASN_ENCODING, ptrCertificate, certificate->Length
	); 
	// ��������� ���������� ������
	AE_CHECK_WINAPI(hCertContext != 0);
	try {
		// �������� ���������� � ���������
		AE_CHECK_WINAPI(::CertAddCertificateContextToStore(
			hCertStore, hCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0
		)); 
	}
	// ������� �������� �����������
	finally { ::CertFreeCertificateContext(hCertContext);  }
}
