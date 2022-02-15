#include "stdafx.h"
#include "Sign.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Sign.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::BSignHash::Sign(IPrivateKey^ privateKey, 
	IRand^ rand, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// ���������� ��� ���������
	String^ algName = GetName(privateKey->Parameters); 

	// ������� ����������������� ��������
	Using<BProviderHandle^> hProvider(gcnew BProviderHandle(provider, algName, 0)); 

	// ������������� ������ ���� �������
	Using<BKeyHandle^> hPrivateKey(ImportPrivateKey(hProvider.Get(), algName, privateKey));
     
	// ��������� ���-��������
	return Sign(privateKey->Parameters, hPrivateKey.Get(), hashAlgorithm, hash);  
}

void Aladdin::CAPI::CNG::BVerifyHash::Verify(IPublicKey^ publicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// ���������� ��� ���������
	String^ algName = GetName(publicKey->Parameters); 

	// ������� ����������������� ��������
	Using<BProviderHandle^> hProvider(gcnew BProviderHandle(provider, algName, 0)); 
    
    // ������������� �������� ���� �������
    Using<BKeyHandle^> hPublicKey(ImportPublicKey(hProvider.Get(), algName, publicKey));

    // ��������� ������� ������
    Verify(publicKey->Parameters, hPublicKey.Get(), hashAlgorithm, hash, signature);
}

array<BYTE>^ Aladdin::CAPI::CNG::NSignHash::Sign(IPrivateKey^ privateKey, 
	IRand^ rand, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// �������� ��������� ������� �����
	NKeyHandle^ hPrivateKey = ((NPrivateKey^)privateKey)->Handle;

	// ��������� ���-��������
	return Sign(privateKey->Scope, privateKey->Parameters, hPrivateKey, hashAlgorithm, hash);
}

array<BYTE>^ Aladdin::CAPI::CNG::NSignHash::Sign(SecurityObject^ scope,
	NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ hash, DWORD flags) 
{$
	// ��� ����� ����������
	if (dynamic_cast<Container^>(scope) != nullptr) 
	{
		// ������������� ��� ����������
		Container^ container = (Container^)scope; 

		// ��������� ���-��������
		return container->SignHash(hPrivateKey, padding, hash, flags); 
	}
	// ��������� ���-��������
	else return hPrivateKey->SignHash(padding, hash, flags);
}

void Aladdin::CAPI::CNG::NVerifyHash::Verify(IPublicKey^ publicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// ������������� �������� ���� �������
	Using<NKeyHandle^> hPublicKey(provider->ImportPublicKey(AT_SIGNATURE, publicKey));
 
	// ��������� ������� ������
	Verify(publicKey->Parameters, hPublicKey.Get(), hashAlgorithm, hash, signature); 
}
