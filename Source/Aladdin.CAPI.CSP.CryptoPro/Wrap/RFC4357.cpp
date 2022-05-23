#include "..\stdafx.h"
#include "..\Provider.h"
#include "..\Cipher\GOST28147.h"
#include "RFC4357.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RFC4357.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ���������� ����� ���� 28147-89 
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::CryptoPro::Wrap::RFC4357::Wrap(
	IRand^ rand, ISecretKey^ KEK, ISecretKey^ CEK)
{$
	// ��������� �������������� ����
	CryptoPro::Provider^ provider = (CryptoPro::Provider^)Provider; 

    // ��� ������������ ������
    if (ukm->Length == SEANCE_VECTOR_LEN && dynamic_cast<CAPI::CSP::SecretKey^>(CEK) != nullptr) 
	{ 
		// ��������� ����� ���������� �����
		Using<CAPI::CSP::KeyHandle^> hKEK;
    
        // ��� ������ ����� ���������� �����
        if (dynamic_cast<CAPI::CSP::SecretKey^>(KEK) != nullptr)
        {
	        // ������� ��������� ����� ���������� ����� 
	        hKEK.Attach(CAPI::CSP::Handle::AddRef(((CAPI::CSP::SecretKey^)KEK)->Handle)); 
        }
        // ��� ������� �������� ����� ���������� �����
        else if (KEK->Value != nullptr)
        {
			// �������� ��� �����
			CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(
				KEK->KeyFactory, KEK->Value->Length
			); 
            // ������� ��������� ����� ���������� �����
            hKEK.Attach(keyType->ConstructKey(Context, KEK->Value, 0));  
        }
        // ��� ������ ��������� ����������
        else throw gcnew InvalidKeyException();  

		// ���������� ������������� ������� �����������
		hKEK.Get()->SetString(KP_CIPHEROID, sboxOID, 0); 

        // ����������� ���� ���������� ������
        return WrapKey(AlgID, ukm, hKEK.Get(), ((CAPI::CSP::SecretKey^)CEK)->Handle);  
    }
    else { 
		// �������� ������ ��� ���������� �������� �����������
		array<BYTE>^ start = gcnew array<BYTE>(SEANCE_VECTOR_LEN); 

		// ������� ��������� �������� �����������
		Array::Copy(ukm, 0, start, 0, start->Length);

        // ������� �������� �������������� �����
        Using<CAPI::KeyDerive^> keyDerive(GetKDFAlgorithm(Context)); 

        // ��������� �������������� �����
        Using<ISecretKey^> deriveKEK(keyDerive.Get()->DeriveKey(KEK, ukm, KeyFactory, 32));

        // ��������� ����� ���������� ������ 
        Using<CAPI::CSP::KeyHandle^> hDeriveKEK; 

        // ��� ������ ����� ���������� �����
        if (dynamic_cast<CAPI::CSP::SecretKey^>(deriveKEK.Get()) != nullptr)
        {
            // ������� ��������� ����� ���������� ����� 
            hDeriveKEK.Attach(CAPI::CSP::Handle::AddRef(
				((CAPI::CSP::SecretKey^)deriveKEK.Get())->Handle
			)); 
	    }
        // ��� ������� �������� ����� ���������� �����
        else if (deriveKEK.Get()->Value != nullptr)
        {
			// �������� ��� �����
			CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(KeyFactory, 32); 

            // ������� ��������� ����� ���������� �����
            hDeriveKEK.Attach(keyType->ConstructKey(Context, deriveKEK.Get()->Value, 0));  
        }
        // ��� ������ ��������� ����������
        else throw gcnew InvalidKeyException();  

	    // ���������� ��������� ��������� ����������
		hDeriveKEK.Get()->SetLong  (KP_MODE     , CRYPT_MODE_ECB, 0); 
		hDeriveKEK.Get()->SetLong  (KP_PADDING  , ZERO_PADDING  , 0); 
		hDeriveKEK.Get()->SetString(KP_CIPHEROID, sboxOID       , 0); 

		// ������� �������� ��������� ������������
		Using<CAPI::CSP::HashHandle^> hHash(Context->CreateHash(
			CALG_G28147_MAC, hDeriveKEK.Get(), 0
		)); 
		// ���������� ��������� ��������
		hHash.Get()->SetParam(HP_HASHSTARTVECT, start, 0); 

		// ��������� �������� ������������
		hHash.Get()->HashData(CEK->Value, 0, CEK->Length, 0); 

		// �������� �������� ������������
		array<BYTE>^ mac = hHash.Get()->GetParam(HP_HASHVAL, 0);

		// ��������� ������������ �������
		if (mac->Length != EXPORT_IMIT_SIZE) throw gcnew InvalidOperationException(); 

		// �������� ������ ��� ����������
		array<BYTE>^ wrapped = gcnew array<BYTE>(CEK->Length + EXPORT_IMIT_SIZE); 

		// ����������� ���� ���������� ������
		hDeriveKEK.Get()->Encrypt(CEK->Value, 0, CEK->Length, TRUE, 0, wrapped, 0); 

		// ����������� �������� ������������
		Array::Copy(mac, 0, wrapped, CEK->Length, mac->Length); return wrapped; 
    }
}

Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::CSP::CryptoPro::Wrap::RFC4357::Unwrap(
	ISecretKey^ KEK, array<BYTE>^ wrapped, SecretKeyFactory^ keyFactory)
{$
	// ��������� �������������� ����
	CryptoPro::Provider^ provider = (CryptoPro::Provider^)Provider; 

	// ���������� ������ �����
	int keySize = wrapped->Length - EXPORT_IMIT_SIZE; 

    // ��������� ������������ �������
    if (keySize != 32 && keySize != 64) throw gcnew NotSupportedException(); 

    // ��� ������������ ������
    if (ukm->Length == SEANCE_VECTOR_LEN) 
	{ 
		// ��������� ����� ���������� �����
		Using<CAPI::CSP::KeyHandle^> hKEK;

	    // ��� ������ ����� ���������� �����
	    if (dynamic_cast<CAPI::CSP::SecretKey^>(KEK) != nullptr)
	    {
		    // ������� ��������� ����� ���������� ����� 
		    hKEK.Attach(CAPI::CSP::Handle::AddRef(((CAPI::CSP::SecretKey^)KEK)->Handle)); 
	    }
        // ��� ������� �������� ����� ���������� �����
        else if (KEK->Value != nullptr)
        {
			// �������� ��� �����
			CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(
				KEK->KeyFactory, KEK->Value->Length
			); 
            // ������� ��������� ����� ���������� �����
            hKEK.Attach(keyType->ConstructKey(Context, KEK->Value, 0));  
        }
        // ��� ������ ��������� ����������
        else throw gcnew InvalidKeyException();  

		// ���������� ������������� ������� �����������
		hKEK.Get()->SetString(KP_CIPHEROID, sboxOID, 0); 

        // ������������ ���� ���������� ������
		Using<CAPI::CSP::KeyHandle^> hCEK(UnwrapKey(Context, AlgID, ukm, hKEK.Get(), wrapped)); 

		// ������� �������������� ����
		return gcnew CAPI::CSP::SecretKey(provider, keyFactory, hCEK.Get());  
	}
    else {  
		// �������� ������ ��� ���������� �������� �����������
		array<BYTE>^ start = gcnew array<BYTE>(SEANCE_VECTOR_LEN); 

		// ������� ��������� �������� �����������
		Array::Copy(ukm, 0, start, 0, start->Length);

        // ������� �������� �������������� �����
        Using<CAPI::KeyDerive^> keyDerive(GetKDFAlgorithm(Context)); 

        // ��������� �������������� �����
        Using<ISecretKey^> deriveKEK(keyDerive.Get()->DeriveKey(KEK, ukm, KeyFactory, 32));

        // ��������� ����� ���������� ������ 
        Using<CAPI::CSP::KeyHandle^> hDeriveKEK; 

        // ��� ������ ����� ���������� �����
        if (dynamic_cast<CAPI::CSP::SecretKey^>(deriveKEK.Get()) != nullptr)
        {
            // ������� ��������� ����� ���������� ����� 
            hDeriveKEK.Attach(CAPI::CSP::Handle::AddRef(
				((CAPI::CSP::SecretKey^)deriveKEK.Get())->Handle
			)); 
        }
        // ��� ������� �������� ����� ���������� �����
        else if (deriveKEK.Get()->Value != nullptr)
        {
			// �������� ��� �����
			CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(KeyFactory, 32); 

            // ������� ��������� ����� ���������� �����
            hDeriveKEK.Attach(keyType->ConstructKey(Context, deriveKEK.Get()->Value, 0));  
        }
        // ��� ������ ��������� ����������
        else throw gcnew InvalidKeyException();

	    // ���������� ��������� ��������� ����������
	    hDeriveKEK.Get()->SetLong  (KP_MODE     , CRYPT_MODE_ECB, 0); 
	    hDeriveKEK.Get()->SetLong  (KP_PADDING  , ZERO_PADDING  , 0); 
	    hDeriveKEK.Get()->SetString(KP_CIPHEROID, sboxOID       , 0); 

		// �������� ������ ��� ����� ���������� ������
		array<BYTE>^ value = gcnew array<BYTE>(keySize); 

	    // ������������ ���� ���������� ������
	    hDeriveKEK.Get()->Decrypt(wrapped, 0, value->Length, TRUE, 0, value, 0); 

		// ������� �������� ��������� ������������
		Using<CAPI::CSP::HashHandle^> hHash(
			Context->CreateHash(CALG_G28147_MAC, hDeriveKEK.Get(), 0)
		); 
		// ���������� ��������� ��������
		hHash.Get()->SetParam(HP_HASHSTARTVECT, start, 0); 

		// ��������� �������� ������������
		hHash.Get()->HashData(value, 0, value->Length, 0); 

		// �������� �������� ������������
		array<BYTE>^ mac = hHash.Get()->GetParam(HP_HASHVAL, 0);

		// ��������� ������������ �������
		if (mac->Length != EXPORT_IMIT_SIZE) throw gcnew InvalidOperationException(); 

		// ��������� ���������� ������������
		if (!Arrays::Equals(mac, 0, wrapped, value->Length, mac->Length)) 
		{
		    // ��� ������ ��������� ����������
			throw gcnew InvalidDataException(); 
		}
		// ������� ����������� ����
		return keyFactory->Create(value);
    }
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �����
///////////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::CryptoPro::Wrap::RFC4357::WrapKey(ALG_ID algID, 
	array<BYTE>^ ukm, CAPI::CSP::KeyHandle^ hKEK, CAPI::CSP::KeyHandle^ hCEK)
{$
	// ��������� ������ �������������
	if (ukm->Length != SEANCE_VECTOR_LEN) throw gcnew NotSupportedException(); 

	// ���������� �������� �������� � ������ �������������
	hKEK->SetLong(KP_ALGID, algID, 0); hKEK->SetParam(KP_IV, ukm, 0);

	// ���������� ������ ������
	DWORD cbBlob = hCEK->Export(hKEK, SIMPLEBLOB, 0, IntPtr::Zero, 0); 

	// �������� ������ ��� ��������� ��������
	std::vector<BYTE> vecBlob(cbBlob); int keySize = hCEK->GetLong(KP_KEYLEN, 0) / 8;

	// �������������� ���� 
	cbBlob = hCEK->Export(hKEK, SIMPLEBLOB, 0, IntPtr(&vecBlob[0]), cbBlob); 

	// �������� ������ ��� ����������
	array<BYTE>^ wrapped = gcnew array<BYTE>(keySize + EXPORT_IMIT_SIZE); 
	
	// ��������� �������������� ����
	if (keySize == 32) { PCRYPT_SIMPLEBLOB pBlob = (PCRYPT_SIMPLEBLOB)&vecBlob[0];

		// ������� ������������� ����
		Marshal::Copy(IntPtr(pBlob->bEncryptedKey), wrapped, 0, keySize); 

		// ������� ������������
		Marshal::Copy(IntPtr(pBlob->bMacKey), wrapped, keySize, EXPORT_IMIT_SIZE); 
	}
	else if (keySize == 64)
	{
		// ��������� �������������� ����
		PCRYPT_SIMPLEBLOB_512 pBlob = (PCRYPT_SIMPLEBLOB_512)&vecBlob[0];

		// ������� ������������� ����
		Marshal::Copy(IntPtr(pBlob->bEncryptedKey), wrapped, 0, keySize); 

		// ������� ������������
		Marshal::Copy(IntPtr(pBlob->bMacKey), wrapped, keySize, EXPORT_IMIT_SIZE); 
	}
	// ��� ������ ��������� ����������
	else throw gcnew NotSupportedException(); return wrapped; 
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::CryptoPro::Wrap::RFC4357::UnwrapKey(
	CAPI::CSP::ContextHandle^ hContext, ALG_ID algID, array<BYTE>^ ukm, 
	CAPI::CSP::KeyHandle^ hKEK, array<BYTE>^ wrapped)
{$
	// ���������� ������ �����
	int keySize = wrapped->Length - EXPORT_IMIT_SIZE; 

	// ��������� ������ �����
	if (keySize != 32 && keySize != 64) throw gcnew InvalidDataException();

	// ���������� �������� ������� � ������ �������������
	hKEK->SetLong(KP_ALGID, algID, 0); hKEK->SetParam(KP_IV, ukm, 0);

	// ������������ �������������� ������� �����������
	array<ASN1::ObjectIdentifier^>^ oids = gcnew array<ASN1::ObjectIdentifier^>(1); 
	
	// ������������ ������������� ������� �����������
	oids[0] = gcnew ASN1::ObjectIdentifier(hKEK->GetString(KP_CIPHEROID, 0)); 

	// �������� �������������� �������������
	array<BYTE>^ encoded = ASN1::Sequence<ASN1::ObjectIdentifier^>(oids).Encoded; 

	// � ����������� �� ������� �����
	if (keySize == 32)
	{
		// ������ ������������� ���������
		BLOBHEADER blobHeader = { SIMPLEBLOB, BLOB_VERSION, 0, CALG_G28147 } ; 

		// ������ ��������� ���������
		CRYPT_SIMPLEBLOB_HEADER header = { blobHeader, G28147_MAGIC, algID }; 

		// ���������� ������ ��������� ��� �������
		DWORD cbBlob = FIELD_OFFSET(CRYPT_SIMPLEBLOB, bEncryptionParamSet) + encoded->Length; 
		
		// �������� ������ ��� ��������� �������
		std::vector<BYTE> vecBlob(cbBlob); PCRYPT_SIMPLEBLOB pBlob = (PCRYPT_SIMPLEBLOB)&vecBlob[0]; 
		
		// ����������� ��������� � ��������� ������
		pBlob->tSimpleBlobHeader = header; Marshal::Copy(ukm, 0, IntPtr(pBlob->bSV), ukm->Length);

		// ����������� ������������� ����
		Marshal::Copy(wrapped, 0, IntPtr(pBlob->bEncryptedKey), keySize); 

		// ����������� ������������
		Marshal::Copy(wrapped, keySize, IntPtr(pBlob->bMacKey), EXPORT_IMIT_SIZE); 

		// ����������� �������������� �������������
		Marshal::Copy(encoded, 0, IntPtr(pBlob->bEncryptionParamSet), encoded->Length); 

		// ������������� ����
		return hContext->ImportKey(hKEK, IntPtr(pBlob), cbBlob, CRYPT_EXPORTABLE); 
	}
	else {
		// ������ ������������� ���������
		BLOBHEADER blobHeader = { SIMPLEBLOB, BLOB_VERSION, 0, CALG_SYMMETRIC_512 } ; 

		// ������ ��������� ���������
		CRYPT_SIMPLEBLOB_HEADER header = { blobHeader, G28147_MAGIC, algID }; 

		// ���������� ������ ��������� ��� �������
		DWORD cbBlob = FIELD_OFFSET(CRYPT_SIMPLEBLOB_512, bEncryptionParamSet) + encoded->Length; 
		
		// �������� ������ ��� ��������� �������
		std::vector<BYTE> vecBlob(cbBlob); PCRYPT_SIMPLEBLOB_512 pBlob = (PCRYPT_SIMPLEBLOB_512)&vecBlob[0]; 
		
		// ����������� ���������
		pBlob->tSimpleBlobHeader = header; Marshal::Copy(ukm, 0, IntPtr(pBlob->bSV), ukm->Length);

		// ����������� ������������� ����
		Marshal::Copy(wrapped, 0, IntPtr(pBlob->bEncryptedKey), keySize); 

		// ����������� ������������
		Marshal::Copy(wrapped, keySize, IntPtr(pBlob->bMacKey), EXPORT_IMIT_SIZE); 

		// ����������� �������������� �������������
		Marshal::Copy(encoded, 0, IntPtr(pBlob->bEncryptionParamSet), encoded->Length); 

		// ������������� ����
		return hContext->ImportKey(hKEK, IntPtr(pBlob), cbBlob, CRYPT_EXPORTABLE); 
	}
}
