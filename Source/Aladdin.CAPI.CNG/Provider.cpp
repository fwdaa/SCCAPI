#include "stdafx.h"
#include "Provider.h"
#include "Container.h"
#include "Key.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NProvider::NProvider(String^ name) 
{$
	// ��������� ���������� ���������
	hProvider = gcnew NProviderHandle(name, 0); this->name = name; 

	// ������� ������ ������ ����������� ������
	secretKeyFactories = gcnew Dictionary<String^, SecretKeyFactory^>(); 
	      keyFactories = gcnew Dictionary<String^,       KeyFactory^>(); 
}

Aladdin::CAPI::CNG::NProvider::~NProvider() 
{$ 
	// ���������� ������� ����������
	CNG::Handle::Release(hProvider); 
} 

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProvider::ImportKeyPair(
	Container^ container, IntPtr hwnd, DWORD keyType, 
	BOOL exportable, IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	// �������� �� ��������������
    throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProvider::ImportKeyPair(
	Container^ container, IntPtr hwnd, NKeyHandle^ hKey, 
	DWORD keyType, String^ typeBlob, IntPtr ptrBlob, DWORD cbBlob, 
	BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags)
{
	// ������������� ���� ������
	return container->ImportKeyPair(hwnd, hKey, keyType, 
		typeBlob, ptrBlob, cbBlob, exportable, action, flags
	); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::CNG::NProvider::ExportPublicKey(NKeyHandle^ hPublicKey)
{$
	// ���������� ��������� ������ ������
	DWORD cbInfo = 0; AE_CHECK_WINAPI(::CryptExportPublicKeyInfo(
		hPublicKey->Value, 0, X509_ASN_ENCODING, 0, &cbInfo
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> vecInfo(cbInfo); PCERT_PUBLIC_KEY_INFO pInfo = 
		(PCERT_PUBLIC_KEY_INFO)&vecInfo[0]; 

	// �������� �������� �����
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfo(
		hPublicKey->Value, 0, X509_ASN_ENCODING, pInfo, &cbInfo
	)); 
	// ���������� ������ ��� ����������� �����
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptEncodeObject(
		X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, 0, &cb
	)); 
	// �������� ������ ��� ����������� �����
	array<BYTE>^ encoded = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrEncoded = &encoded[0]; 

	// ������������ ����
	AE_CHECK_WINAPI(::CryptEncodeObject(
		X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, ptrEncoded, &cb
	));
	// ������������� �������� ����
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(
		ASN1::Encodable::Decode(encoded, 0, cb)
	); 
}

Aladdin::CAPI::CNG::NPrivateKey^ Aladdin::CAPI::CNG::NProvider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, NKeyHandle^ hKeyPair)
{$
	// ������� ������ ����
	return gcnew NPrivateKey(this, scope, publicKey, hKeyPair); 
}

