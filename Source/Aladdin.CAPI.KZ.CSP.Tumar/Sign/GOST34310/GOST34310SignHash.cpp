#include "..\..\stdafx.h"
#include "..\..\Container.h"
#include "GOST34310SignHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310SignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� ���� � 34.10-2001, 2012
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::KZ::CSP::Tumar::Sign::GOST34310::SignHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// �������� �������� �����������
	Using<IAlgorithm^> algorithm(Provider->CreateAlgorithm<CAPI::Hash^>(nullptr, hashAlgorithm)); 

	// ��������� ��������� ��������� �����������
	if (algorithm.Get() == nullptr) throw gcnew NotSupportedException();

    // ������� �������� �����������
    return hContext->CreateHash(hashID, nullptr, 0); 
}

array<BYTE>^ Aladdin::CAPI::KZ::CSP::Tumar::Sign::GOST34310::SignHash::Sign(
	IPrivateKey^ privateKey, IRand^ rand, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// ������������� ��� �����
	CAPI::CSP::PrivateKey^ cspPrivateKey = (CAPI::CSP::PrivateKey^)privateKey; 

	// ��������� ������� ����������
	if (privateKey->Container == nullptr) throw gcnew InvalidKeyException();

	// �������� ��������� �����
	Container^ container = (Container^)privateKey->Container; 

	// �������������� �������� ����
	Container::SetActivePrivateKey active(container, cspPrivateKey); 

	// ������� ������� �������
	array<BYTE>^ signature = CAPI::CSP::SignHash::Sign(privateKey, rand, hashAlgorithm, hash); 

	// �������� ������� ������
	Array::Reverse(signature); return signature; 
}

