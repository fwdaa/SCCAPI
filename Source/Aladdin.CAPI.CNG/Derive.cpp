#include "stdafx.h"
#include "Derive.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Derive.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ������������ ������ �����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::CNG::BKeyAgreement::DeriveKey(	    
	IPrivateKey^ privateKey, IPublicKey^ publicKey, 
	array<BYTE>^ random, SecretKeyFactory^ keyType, int keySize)
{$
	// ���������� ��� ���������
	String^ algName = GetName(privateKey->Parameters); 

	// ������� ����������������� ��������
	Using<BProviderHandle^> hProvider(gcnew BProviderHandle(provider, algName, 0)); 

	// ������������� ������ ����
	Using<BKeyHandle^> hPrivateKey(ImportPrivateKey(hProvider.Get(), algName, privateKey));

	// ������������� �������� ����
	Using<BKeyHandle^> hPublicKey(ImportPublicKey(hProvider.Get(), algName, publicKey));

	// ��������� ���������� �������
	Using<BSecretHandle^> hSecret(AgreementSecret(hPrivateKey.Get(), hPublicKey.Get()));

	// ��������� ������������ ������ �����
	return keyType->Create(DeriveKey(privateKey->Parameters, hSecret.Get(), random, keySize));  
}

Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::CNG::NKeyAgreement::DeriveKey(	    
	IPrivateKey^ privateKey, IPublicKey^ publicKey, 
	array<BYTE>^ random, SecretKeyFactory^ keyFactory, int keySize)
{$
	// �������� ��������� ������� �����
	NKeyHandle^ hPrivateKey = ((NPrivateKey^)privateKey)->Handle;

	// �������� ������������ ���������
	NProvider^ provider = (NProvider^)privateKey->Factory; 

	// ������������� �������� ���� �������
	Using<NKeyHandle^> hPublicKey(provider->ImportPublicKey(AT_KEYEXCHANGE, publicKey));

	// ��������� ���������� �������
	Using<CAPI::CNG::NSecretHandle^> hSecret(AgreementSecret(
		privateKey->Scope, hPrivateKey, hPublicKey.Get()
	));
	// ��������� ������������ ������ �����
	return keyFactory->Create(DeriveKey(privateKey->Parameters, hSecret.Get(), random, keySize)); 
}

Aladdin::CAPI::CNG::NSecretHandle^ Aladdin::CAPI::CNG::NKeyAgreement::AgreementSecret(
	SecurityObject^ scope, NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey, DWORD flags)
{$
	// ��� ����� ����������
	if (dynamic_cast<Container^>(scope) != nullptr) 
	{
		// ������������� ��� ����������
		Container^ container = (Container^)scope; 

		// ����������� ����� ����
		return container->AgreementSecret(hPrivateKey, hPublicKey, flags); 
	}
	// ����������� ����� ����
	else return hPrivateKey->AgreementSecret(hPublicKey, flags);
}

