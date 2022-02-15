#include "stdafx.h"
#include "Keyx.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Keyx.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������������� �������� ����������
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::Encipherment::Encrypt( 
	IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data)
{$
	// ������������� �������� ����
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, publicKey, AT_KEYEXCHANGE
	));  
	// ����������� ������
	return hPublicKey.Get()->Encrypt(data, flags); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Decipherment::Decrypt(
	IPrivateKey^ privateKey, array<BYTE>^ data)
{$
	// �������� ��������� ������� �����
	Using<KeyHandle^> hPrivateKey(((PrivateKey^)privateKey)->OpenHandle());

	// ��� ����� �� ����������
	if (privateKey->Container != nullptr)
	{
		// �������� ��������� �����
		Container^ container = (Container^)(privateKey->Container);  
 
		// ������������ ������
		return container->Decrypt(hPrivateKey.Get(), data, flags); 
	}
	// ������������ ������
	else return hPrivateKey.Get()->Decrypt(data, flags);
}

///////////////////////////////////////////////////////////////////////////
// �������� ������������ �����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::CSP::KeyAgreement::DeriveKey(
	IPrivateKey^ privateKey, IPublicKey^ publicKey, 
	array<BYTE>^ random, SecretKeyFactory^ keyFactory, int keySize)
{$
	// ������������� �������� ����
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, publicKey, AT_KEYEXCHANGE
	));
	// ���������� ������ ������
	DWORD cbBlob = hPublicKey.Get()->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0);

	// �������� ������ ��� ��������� ��������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// �������������� �������� ����
	cbBlob = hPublicKey.Get()->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr(ptrBlob), cbBlob);

	// �������� ��������� ������� �����
	Using<KeyHandle^> hPrivateKey(((PrivateKey^)privateKey)->OpenHandle()); 

	// ��� ����� �� ���������� 
	if (privateKey->Container != nullptr)
	{
		// �������� ��������� ��� ������� �����
		Container^ container = (Container^)(privateKey->Container); 

		// ����������� ����
		Using<KeyHandle^> hKey(container->ImportKey(
			hPrivateKey.Get(), IntPtr(ptrBlob), cbBlob, flags | CRYPT_EXPORTABLE
		)); 
		// ���������� ��������� �����
		SetKeyParameters(container->Handle, hKey.Get(), random, keySize); 

		// ��� ���������� ���������
		if (container->Handle->Value == provider->Handle->Value) 
		{
			// ������� ������ �����
			return gcnew SecretKey(provider, keyFactory, hKey.Get());
		}
		// �������� ��� �����
		SecretKeyType^ keyType = provider->GetSecretKeyType(keyFactory, keySize); 

		// ������� �������� �����
		return keyFactory->Create(keyType->GetKeyValue(container->Handle, hKey.Get())); 
	}
	else {
		// ����������� ����
		Using<KeyHandle^> hKey(provider->Handle->ImportKey(
			hPrivateKey.Get(), IntPtr(ptrBlob), cbBlob, flags | CRYPT_EXPORTABLE
		));
		// ���������� ��������� �����
		SetKeyParameters(provider->Handle, hKey.Get(), random, keySize);
 
		// ������� ������������� ����
		return gcnew SecretKey(provider, keyFactory, hKey.Get());  
	}
}

///////////////////////////////////////////////////////////////////////////
// �������� ������ �����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::TransportKeyData^ 
Aladdin::CAPI::CSP::TransportKeyWrap::Wrap(
	ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
	IPublicKey^ publicKey, IRand^ rand, ISecretKey^ CEK) 
{$
	// ������������� �������� ����
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, publicKey, AT_KEYEXCHANGE
	));  
	// ��� ������� ������� �����
	Using<KeyHandle^> hCEK; if (dynamic_cast<SecretKey^>(CEK) != nullptr)
	{
		// ������� ��������� �����
		hCEK.Attach(Handle::AddRef(((SecretKey^)CEK)->Handle)); 
	}
    // ��� ������� �������� �����
    else if (CEK->Value != nullptr)
    {
		// �������� ��� �����
		SecretKeyType^ keyType = provider->GetSecretKeyType(
			CEK->KeyFactory, CEK->Value->Length
		); 
        // ������� ���� ��� ���������
		hCEK.Attach(keyType->ConstructKey(
			hContext, CEK->Value, CRYPT_EXPORTABLE
		));
    }
    // ��� ������ ��������� ����������
    else throw gcnew InvalidKeyException();  

    // ���������� ��������� ������ ������
    DWORD cbBlob = hCEK.Get()->Export(hPublicKey.Get(), SIMPLEBLOB, flags, IntPtr::Zero, 0); 

    // �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
    PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob;
		   
	// ��������� ������� �����
    cbBlob = hCEK.Get()->Export(hPublicKey.Get(), SIMPLEBLOB, flags, IntPtr(pBlob), cbBlob);

    // ���������� �������� �������������� �����
    DWORD offsetKey = sizeof(PUBLICKEYSTRUC) + sizeof(ALG_ID);

    // �������� ����� ��� �������������� �����
    array<BYTE>^ encryptedKey = gcnew array<BYTE>(cbBlob - offsetKey);

    // ����������� ������������� ����
    Array::Copy(blob, offsetKey, encryptedKey, 0, encryptedKey->Length); 

    // ������� ������������� ����
    return gcnew TransportKeyData(algorithmParameters, encryptedKey);    
}

Aladdin::CAPI::ISecretKey^ 
Aladdin::CAPI::CSP::TransportKeyUnwrap::Unwrap(
	IPrivateKey^ privateKey, TransportKeyData^ transportData, SecretKeyFactory^ keyFactory)
{$
	// ��������� ������� ����������
	if (transportData == nullptr) throw gcnew ArgumentException(); 

	// �������� ��� �����
	SecretKeyType^ keyType = provider->GetSecretKeyType(keyFactory, 0); 

    // ������ ������������� ���������
    BLOBHEADER blobHeader = { SIMPLEBLOB, CUR_BLOB_VERSION, 0, keyType->AlgID };

    // ���������� �������� �������������� �����
    DWORD offsetKey = sizeof(PUBLICKEYSTRUC) + sizeof(ALG_ID);

    // ������� ������������� ����
    array<BYTE>^ encryptedKey = transportData->EncryptedKey;  

    // ���������� ������ ������ ��� �������
    DWORD cbBlob = offsetKey + encryptedKey->Length; 

	// �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
    PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; *pBlob = blobHeader; 

    // ������� ������������� ��������� �����
    *(ALG_ID*)(pBlob + 1) = GetPublicKeyID(privateKey->Parameters);

    // ����������� �������� �������������� �����
    Array::Copy(encryptedKey, 0, blob, offsetKey, encryptedKey->Length);  

	// �������� ��������� ������� �����
	Using<KeyHandle^> hPrivateKey(((PrivateKey^)privateKey)->OpenHandle()); 

	// ��� ����� �� ����������
	if (privateKey->Container != nullptr)
	{
		// ������������� ��� ����������
		Container^ container = (Container^)(privateKey->Container); 

		// ������������� ����
		Using<KeyHandle^> hCEK(container->ImportKey(
			hPrivateKey.Get(), IntPtr(pBlob), cbBlob, flags | CRYPT_EXPORTABLE
		));
		// ������� �������� �����
		return keyFactory->Create(keyType->GetKeyValue(container->Handle, hCEK.Get())); 
	}
	else {
		// ������������� ����
		Using<KeyHandle^> hCEK(provider->ImportKey(nullptr, 
			hPrivateKey.Get(), IntPtr(pBlob), cbBlob, flags | CRYPT_EXPORTABLE
		)); 
		// ������� �������� �����
		return keyFactory->Create(keyType->GetKeyValue(provider->Handle, hCEK.Get())); 
	}
}

