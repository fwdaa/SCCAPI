#include "..\..\stdafx.h"
#include "GOST34310VerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310VerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� ���� � 34.10-2001, 2012
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::KZ::CSP::Tumar::Sign::GOST34310::VerifyHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// �������� �������� �����������
	Using<IAlgorithm^> algorithm(Provider->CreateAlgorithm<CAPI::Hash^>(nullptr, hashAlgorithm)); 

	// ��������� ��������� ��������� �����������
	if (algorithm.Get() == nullptr) throw gcnew NotSupportedException();

    // ������� �������� �����������
    return hContext->CreateHash(hashID, nullptr, 0); 
}

