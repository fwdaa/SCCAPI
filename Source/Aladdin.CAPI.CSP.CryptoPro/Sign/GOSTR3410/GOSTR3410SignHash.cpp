#include "..\..\stdafx.h"
#include "GOSTR3410SignHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOSTR3410SignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� ���� � 34.10-2001, 2012
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ 
Aladdin::CAPI::CSP::CryptoPro::Sign::GOSTR3410::SignHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// �������� �������� �����������
	Using<IAlgorithm^> algorithm(Provider->CreateAlgorithm<CAPI::Hash^>(nullptr, hashAlgorithm)); 

	// ��������� ��������� ��������� �����������
	if (algorithm.Get() == nullptr) throw gcnew NotSupportedException();

    // ������� �������� �����������
    return hContext->CreateHash(hashID, nullptr, 0); 
}

