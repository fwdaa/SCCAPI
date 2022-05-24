#include "stdafx.h"
#include "CertificateStore.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "CertificateStore.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ����������� �������� CAPI � MMC Certificates
// Root		- Trusted Root Certification Authorities
// AuthRoot - Third-Party Root Certification Authorities
// Trust	- Enterprise Trust
// CA		- Intermediate Certification Authorities
// My		- Personal
///////////////////////////////////////////////////////////////////////////
 
//////////////////////////////////////////////////////////////////////////////
// ��������� ������������
//////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::CertificateStore::CertificateStore(
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

Aladdin::CAPI::CSP::CertificateStore::~CertificateStore() 
{$
	// ���������� ��������� ���������
	::CertCloseStore(hCertStore, 0); 
}

array<BYTE>^ Aladdin::CAPI::CSP::CertificateStore::FindIssuer(
	array<BYTE>^ certificate)
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
		// ����� ���������� � ���������
		PCCERT_CONTEXT hCertIssuer = ::CertFindCertificateInStore(hCertStore, 
			X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, hCertContext, 0
		); 
		// ��������� ������� �����������
		if (hCertIssuer == 0) return nullptr; 

		// �������� ����� ��� �����������
		array<BYTE>^ encoded = gcnew array<BYTE>(hCertIssuer->cbCertEncoded); 

		// ����������� �������������� �������������
		Marshal::Copy(IntPtr(hCertIssuer->pbCertEncoded), encoded, 0, encoded->Length); 

		return encoded; 
	}
	// ������� �������� �����������
	finally { ::CertFreeCertificateContext(hCertContext); }
}

array<BYTE>^ Aladdin::CAPI::CSP::CertificateStore::Find(PCERT_PUBLIC_KEY_INFO pInfo)
{$
	// ����� ���������� � ���������
	PCCERT_CONTEXT hCertContext = ::CertFindCertificateInStore(
		hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_PUBLIC_KEY, pInfo, 0
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

array<BYTE>^ Aladdin::CAPI::CSP::CertificateStore::Find(
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
	std::vector<BYTE> vecInfo(cbInfo); PCERT_PUBLIC_KEY_INFO pInfo = 
		(PCERT_PUBLIC_KEY_INFO)&vecInfo[0]; 

	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
		ptrEncoded, cbEncoded, CRYPT_DECODE_NOCOPY_FLAG, pInfo, &cbInfo
	)); 
	// ����� ���������� � ���������
	return Find(pInfo); 
}

void Aladdin::CAPI::CSP::CertificateStore::Write(array<BYTE>^ certificate)
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

array<Aladdin::CAPI::Certificate^>^ 
Aladdin::CAPI::CSP::CertificateStore::GetCertificateChain(
	String^ provider, DWORD location, Certificate^ certificate)
{$
    // ���������������� ������� ������������
    List<Certificate^>^ certificateChain = gcnew List<Certificate^>(
		gcnew array<Certificate^> { certificate }
    ); 
	// ������� ���������
	CertificateStore storeRoot (provider, "Root"    , location);
	CertificateStore storeAuth (provider, "AuthRoot", location);
	CertificateStore storeTrust(provider, "Trust"   , location);
	CertificateStore storeCA   (provider, "CA"      , location);

    // �� ��������� ���������������� �����������
    while (!PKI::IsSelfSignedCertificate(certificate))
    {
		// ����� ���������� ��������
		array<BYTE>^ encoded = storeRoot.FindIssuer(certificate->Encoded); 

		// ��� ���������� �����������
		if (encoded == nullptr) 
		{
			// ����� ���������� ��������
			encoded = storeAuth.FindIssuer(certificate->Encoded); 
		}
		// ��� ���������� �����������
		if (encoded == nullptr) 
		{
			// ����� ���������� ��������
			encoded = storeTrust.FindIssuer(certificate->Encoded); 
		}
		// ��� ���������� �����������
		if (encoded == nullptr) 
		{
			// ����� ���������� ��������
			encoded = storeCA.FindIssuer(certificate->Encoded); 
		}
		// ��������� ������� �����������
		if (encoded == nullptr) break; 

		// ������������� ����������
		certificate = gcnew Certificate(encoded); 

        // �������� ���������� �������� � ������
        certificateChain->Add(certificate); 
    }
    // ������� ������� ������������
    return certificateChain->ToArray(); 

}

void Aladdin::CAPI::CSP::CertificateStore::SetCertificateChain(
	String^ provider, DWORD location, 
	array<Certificate^>^ certificateChain, int offset)
{$
	// ������� ���������
	CertificateStore storeCA(provider, "CA", location); 

	// ������� ���������
	if (offset == 0) { CertificateStore storeMy(provider, "My", location);

		// ��������� ���������� ��������� �����
		storeMy.Write(certificateChain[offset]->Encoded); offset++; 
	}
	// ��� ���������� ������������
	for (int i = offset; i < certificateChain->Length - 1; i++)
	{
		// ��������� ���������� ��������� �����
		storeCA.Write(certificateChain[i]->Encoded); 
	}
	// ��� ���������� �����������
	if (certificateChain->Length > 1)
	{
		// ������� ����������
		Certificate^ certificate = certificateChain[certificateChain->Length - 1]; 

		// ��� ������������������ �����������
		if (!PKI::IsSelfSignedCertificate(certificate))
		{
			// ��������� ���������� ��������� �����
			storeCA.Write(certificate->Encoded); 
		}
		else {
			// ������� ���������
			CertificateStore storeAuth(provider, "AuthRoot", location);

			// ��������� ���������� ��������� �����
			storeAuth.Write(certificate->Encoded); 
		}
	}
}
