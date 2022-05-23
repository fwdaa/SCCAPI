#include "..\..\stdafx.h"
#include "DSASignHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSASignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� DSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::CSP::Microsoft::Sign::DSA::SignHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// ���������� ������������� ��������� �����������
	String^ hashOID = hashAlgorithm->Algorithm->Value; 

	// ��������� ������������� ��������� �����������
	if (hashOID != ASN1::ANSI::OID::ssig_sha1) throw gcnew NotSupportedException();

	// ������� �������� �����������
	return hContext->CreateHash(CALG_SHA1, nullptr, 0); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Microsoft::Sign::DSA::SignHash::Sign(
	IPrivateKey^ privateKey, IRand^ rand, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// ��������� ���-��������
	array<BYTE>^ signature = CAPI::CSP::SignHash::Sign(privateKey, rand, hashAlgorithm, hash); 

	// ���������� �������� ���������
	int bytesR = ((ANSI::X957::IParameters^)privateKey->Parameters)->Q->BitLength / 8; 

	// ��������� ������ �������
	if (signature->Length <= bytesR) throw gcnew InvalidDataException();

	// ���������� ������ ��������� S
	int bytesS = signature->Length - bytesR; 

	// ������������� ��������� R � S
	Math::BigInteger^ R = Math::Convert::ToBigInteger(signature,      0, bytesR, Endian); 
	Math::BigInteger^ S = Math::Convert::ToBigInteger(signature, bytesR, bytesS, Endian); 

	// ������������ �������
	return Aladdin::ASN1::ANSI::X957::DssSigValue(
		gcnew Aladdin::ASN1::Integer(R), gcnew Aladdin::ASN1::Integer(S)).Encoded; 
}
