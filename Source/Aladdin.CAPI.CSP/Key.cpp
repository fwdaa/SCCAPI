#include "stdafx.h"
#include "Key.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Key.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������� �������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::SecretKeyType::ConstructKey(
    ContextHandle^ hContext, array<BYTE>^ value, DWORD flags) 
{$
    // ������ ������������� ���������
    BLOBHEADER blobHeader = { PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, algID };

	// ���������� �������� �����
	DWORD offsetKey = sizeof(BLOBHEADER) + sizeof(DWORD); 
	
	// ���������� ��������� ������ ������
	DWORD cbBlob = offsetKey + value->Length;
				 
	// �������� ������ ��� ��������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	BLOBHEADER* pBlob = (BLOBHEADER*)(PBYTE)ptrBlob;  

	// ����������� ��������� � ������� ������ �����
	*pBlob = blobHeader; *(PDWORD)(pBlob + 1) = value->Length;

    // ����������� ���������� �����
    Array::Copy(value, 0, blob, offsetKey, value->Length); 

    // ������������� ���� � ��������
    return hContext->ImportKey(nullptr, IntPtr(pBlob), cbBlob, flags); 
}

array<BYTE>^ Aladdin::CAPI::CSP::SecretKeyType::GetKeyValue(
	ContextHandle^ hContext, KeyHandle^ hKey)
{$
	// ���������� ������ ������
	DWORD cbBlob = hKey->Export(nullptr, PLAINTEXTKEYBLOB, 0, IntPtr::Zero, 0);

	// �������� ������ ��� ��������� ��������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	BLOBHEADER* pBlob = (BLOBHEADER*)(PBYTE)ptrBlob;  

	// �������������� ����
	cbBlob = hKey->Export(nullptr, PLAINTEXTKEYBLOB, 0, IntPtr(pBlob), cbBlob);

	// �������� �������� �����
	DWORD offsetKey = sizeof(BLOBHEADER) + sizeof(DWORD);

	// ��������� ������ ������
	if (cbBlob < offsetKey) throw gcnew Win32Exception(NTE_BAD_DATA);

	// �������� ������ ��� �����
	array<BYTE>^ key = gcnew array<BYTE>(*(PDWORD)(pBlob + 1));

	// ��������� ������ �����
	if (cbBlob < offsetKey + key->Length) throw gcnew Win32Exception(NTE_BAD_DATA);

	// ������� �������� �����
	Array::Copy(blob, offsetKey, key, 0, key->Length); return key; 
}

///////////////////////////////////////////////////////////////////////////
// ���� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKey::SecretKey(
	CSP::Provider^ provider, SecretKeyFactory^ keyFactory, KeyHandle^ hKey)
{   
	// ��������� ���������� ���������
	this->provider = RefObject::AddRef(provider); 
	
	// ��������� ���������� ���������
	this->hKey = CSP::Handle::AddRef(hKey); this->keyFactory = keyFactory; 
} 

Aladdin::CAPI::CSP::SecretKey::~SecretKey() 
{ 
	// ���������� ���������� �������
	CSP::Handle::Release(hKey); RefObject::Release(provider); 
} 

int Aladdin::CAPI::CSP::SecretKey::Length::get()
{
    // ��������� ������� ������� �����
    if (value != nullptr) return value->Length; 

    // ������� ������ �����
    return (Handle->GetLong(KP_KEYLEN, 0) + 7) / 8; 
}

array<BYTE>^ Aladdin::CAPI::CSP::SecretKey::Value::get()
try {$
	// ��������� ������� ��������
	if (value != nullptr) return value; 

	// �������� ��� �����
	SecretKeyType^ keyType = provider->GetSecretKeyType(KeyFactory, Length); 

	// �������� �������� �����
	value = keyType->GetKeyValue(provider->Handle, Handle); return value; 
}
// ���������� ��������� ������
catch (Exception^) { return nullptr; }

///////////////////////////////////////////////////////////////////////////
// ������ ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::PrivateKey::PrivateKey(Provider^ provider, SecurityObject^ scope, 
	IPublicKey^ publicKey, KeyHandle^ hPrivateKey, array<BYTE>^ keyID, DWORD keyType) 
		: CAPI::PrivateKey(provider, scope, publicKey->KeyOID)
{ 
	// ��������� ���������� ���������
	this->parameters = publicKey->Parameters; this->keyID = keyID; 

	// ��������� ���������� ���������
	this->hPrivateKey = nullptr; this->keyType = keyType; 

	// ��� ���������� ����� ��������� ��������� �����
	if (Container == nullptr) this->hPrivateKey = Handle::AddRef(hPrivateKey); 
}  

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::PrivateKey::OpenHandle() 
{$ 
	// ��� ���������� ����� ��������� ������� ������ ���������
	if (Container == nullptr) return Handle::AddRef(hPrivateKey);  
	else {
		// ������������� ��� ����������
		CAPI::CSP::Container^ container = (CAPI::CSP::Container^)Container; 

		// �������� ��������� �����
		DWORD keyType; return container->GetUserKey(keyID, OUT keyType); 
	}
}

/*
void Aladdin::CAPI::CSP::PrivateKey::SetCertificateContext(PCCERT_CONTEXT pCertificateContext)
{$
	// ������������� ��� �������
	CSP::Container^ container = dynamic_cast<CSP::Container^>(Container); 

	// ��������� ��� �������
	if (container == nullptr) AE_CHECK_WINERROR(NTE_BAD_KEY); 

	// ������� �������� ����������� � ������
	container->SetCertificateContext(pCertificateContext, keyType); 
}
*/

array<BYTE>^ Aladdin::CAPI::CSP::PrivateKey::Export(KeyHandle^ hExportKey, DWORD flags)
{$
	// ��� ����� ����������
	if (dynamic_cast<CAPI::CSP::Container^>(Container) != nullptr)
	{
		// ������������� ��� ����������
		CAPI::CSP::Container^ container = (CAPI::CSP::Container^)Container; 
		
		// �������� ��������� �����
		Using<KeyHandle^> hPrivateKey(OpenHandle());

		// �������������� ����
		return container->ExportKey(hPrivateKey.Get(), hExportKey, PRIVATEKEYBLOB, flags); 
	}
	else {
		// ���������� ������ ������
		DWORD cbBlob = hPrivateKey->Export(hExportKey, PRIVATEKEYBLOB, flags, IntPtr::Zero, 0); 

		// �������� ������ ��� ��������� ��������
		array<BYTE>^ buffer = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

		// �������������� ����
		cbBlob = hPrivateKey->Export(hExportKey, PRIVATEKEYBLOB, flags, IntPtr(ptrBuffer), cbBlob);

		// �������� ������ ������
		Array::Resize(buffer, cbBlob); return buffer; 
	}
} 

