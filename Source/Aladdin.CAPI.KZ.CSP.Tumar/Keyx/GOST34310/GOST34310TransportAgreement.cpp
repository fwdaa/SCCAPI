#include "..\..\stdafx.h"
#include "..\..\Container.h"
#include "GOST34310TransportAgreement.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310TransportAgreement.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ������������ �����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::TransportAgreementData^ Aladdin::CAPI::KZ::CSP::Tumar::Keyx::GOST34310::TransportAgreement::Wrap(
	IPrivateKey^ privateKey, IPublicKey^ publicKey, 
	array<IPublicKey^>^ recipientPublicKeys, IRand^ rand, ISecretKey^ CEK)
{$
	// ������������� ��� �����
	CAPI::CSP::PrivateKey^ cspPrivateKey = (CAPI::CSP::PrivateKey^)privateKey; 

	// ��������� ��� �����
	if (cspPrivateKey->KeyType != AT_KEYEXCHANGE) throw gcnew InvalidKeyException(); 

	// ��������� ������������ ��������
	if (privateKey->Container == nullptr) throw gcnew InvalidKeyException();

    // ������������� ��� ����������
    Container^ container = (Container^)privateKey->Container; 

	// ��� ������� ������� �����
	Using<CAPI::CSP::KeyHandle^> hCEK; if (dynamic_cast<CAPI::CSP::SecretKey^>(CEK) != nullptr)
	{
		// ������� ��������� �����
		hCEK.Attach(CAPI::CSP::Handle::AddRef(((CAPI::CSP::SecretKey^)CEK)->Handle)); 
	}
	// ��� ������� �������� �����
	else if (CEK->Value != nullptr)
	{
		// �������� ��� �����
		CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(
			CEK->KeyFactory, CEK->Value->Length
		); 
		// ������� ���� ��� ���������
		hCEK.Attach(keyType->ConstructKey(container->Handle, CEK->Value, CRYPT_EXPORTABLE));  
	}
	// ��� ������ ��������� ����������
	else throw gcnew InvalidKeyException();  

	// �������������� �������� ����
	Container::SetActivePrivateKey active(container, cspPrivateKey); 

	// �������� ����� ���������� �������
	array<array<BYTE>^>^ encryptedKeys = gcnew array<array<BYTE>^>(recipientPublicKeys->Length); 

	// ��� ���� �����������
	for (int i = 0; i < encryptedKeys->Length; i++)
	{
		// ������������� �������� ����
		Using<CAPI::CSP::KeyHandle^> hPublicKey(provider->ImportPublicKey(
			container->Handle, recipientPublicKeys[i], cspPrivateKey->KeyType
		));  
		// �������� ������ ��������
		DWORD keyMix = container->Handle->GetLong(PP_KEYMIX, 0);

		// ������� ������ ��������
		container->Handle->SetLong(PP_KEYMIX, 1, 0); 
		try { 				 
			// �������������� ����
			encryptedKeys[i] = container->ExportKey(hCEK.Get(), hPublicKey.Get(), SIMPLEBLOB, flags);	
		}
		// ������������ ������ ��������
		finally { container->Handle->SetLong(PP_KEYMIX, keyMix, 0); }
	}
	// ������� ������������� �����
	return gcnew TransportAgreementData(publicKey, nullptr, encryptedKeys); 
}

Aladdin::CAPI::ISecretKey^ 
Aladdin::CAPI::KZ::CSP::Tumar::Keyx::GOST34310::TransportAgreement::Unwrap(
	IPrivateKey^ recipientPrivateKey, IPublicKey^ publicKey, 
	array<BYTE>^ random, array<BYTE>^ encryptedKey, SecretKeyFactory^ keyFactory)
{$
	// ������������� ��� �����
	CAPI::CSP::PrivateKey^ cspPrivateKey = (CAPI::CSP::PrivateKey^)recipientPrivateKey; 

	// ��������� ��� �����
	if (cspPrivateKey->KeyType != AT_KEYEXCHANGE) throw gcnew InvalidKeyException(); 

	// ��������� ������������ ��������
	if (cspPrivateKey->Container == nullptr) throw gcnew InvalidKeyException();

    // ������������� ��� ����������
    Container^ container = (Container^)cspPrivateKey->Container; 

	// �������� ����� ������
	pin_ptr<BYTE> ptrBlob = &encryptedKey[0]; DWORD cbBlob = encryptedKey->Length; 
	
	// �������������� �������� ����
	Container::SetActivePrivateKey active(container, cspPrivateKey); 

	// ������������� �������� ����
	Using<CAPI::CSP::KeyHandle^> hPublicKey(provider->ImportPublicKey(
		container->Handle, publicKey, cspPrivateKey->KeyType
	));  
	// �������� ������ �������
	DWORD keyMix = container->Handle->GetLong(PP_KEYMIX, 0);

	// ������� ������ �������
	container->Handle->SetLong(PP_KEYMIX, 1, 0); 
	try {
		// ������������� ����
		Using<CAPI::CSP::KeyHandle^> hCEK(container->ImportKey(
			hPublicKey.Get(), IntPtr(ptrBlob), cbBlob, flags | CRYPT_EXPORTABLE
		)); 
		// �������� ��� �����
		CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(keyFactory, 32); 

		// �������� �������� �����
		return keyFactory->Create(keyType->GetKeyValue(container->Handle, hCEK.Get()));
	}
	// ������������ ������ �������
	finally { container->Handle->SetLong(PP_KEYMIX, keyMix, 0); }
}

