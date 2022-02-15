#include "..\..\stdafx.h"
#include "DSAVerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSAVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� DSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::ANSI::CSP::Microsoft::Sign::DSA::VerifyHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// ���������� ������������� ��������� �����������
	String^ hashOID = hashAlgorithm->Algorithm->Value; 

	// ��������� ������������� ��������� �����������
	if (hashOID != ASN1::ANSI::OID::ssig_sha1) throw gcnew NotSupportedException();

	// ������� �������� �����������
	return hContext->CreateHash(CALG_SHA1, nullptr, 0); 
}

void Aladdin::CAPI::ANSI::CSP::Microsoft::Sign::DSA::VerifyHash::Verify(
	IPublicKey^ publicKey, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
	array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// ���������� �������� ���������
	int bytesR = ((ANSI::X957::IParameters^)publicKey->Parameters)->Q->BitLength / 8; 

	// ������������� �������� �������
	Aladdin::ASN1::ANSI::X957::DssSigValue^ encoded = 
		gcnew Aladdin::ASN1::ANSI::X957::DssSigValue(
			Aladdin::ASN1::Encodable::Decode(signature)
	); 
	// ������������ ��������� R � S
	array<BYTE>^ R = Math::Convert::FromBigInteger(encoded->R->Value, Endian, bytesR); 
	array<BYTE>^ S = Math::Convert::FromBigInteger(encoded->S->Value, Endian, bytesR); 

	// ���������� ��������� R � S
	signature = Arrays::Concat(R, S); 

	// ��������� �������
	CAPI::CSP::VerifyHash::Verify(publicKey, hashAlgorithm, hash, signature); 
}

