#include "..\..\stdafx.h"
#include "DSAVerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSAVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения DSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::ANSI::CSP::Microsoft::Sign::DSA::VerifyHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// определить идентификатор алгоритма хэширования
	String^ hashOID = hashAlgorithm->Algorithm->Value; 

	// проверить идентификатор алгоритма хэширования
	if (hashOID != ASN1::ANSI::OID::ssig_sha1) throw gcnew NotSupportedException();

	// создать алгоритм хэширования
	return hContext->CreateHash(CALG_SHA1, nullptr, 0); 
}

void Aladdin::CAPI::ANSI::CSP::Microsoft::Sign::DSA::VerifyHash::Verify(
	IPublicKey^ publicKey, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
	array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// определить параметр алгоритма
	int bytesR = ((ANSI::X957::IParameters^)publicKey->Parameters)->Q->BitLength / 8; 

	// раскодировать значение подписи
	Aladdin::ASN1::ANSI::X957::DssSigValue^ encoded = 
		gcnew Aladdin::ASN1::ANSI::X957::DssSigValue(
			Aladdin::ASN1::Encodable::Decode(signature)
	); 
	// закодировать параметры R и S
	array<BYTE>^ R = Math::Convert::FromBigInteger(encoded->R->Value, Endian, bytesR); 
	array<BYTE>^ S = Math::Convert::FromBigInteger(encoded->S->Value, Endian, bytesR); 

	// объединить параметры R и S
	signature = Arrays::Concat(R, S); 

	// проверить подпись
	CAPI::CSP::VerifyHash::Verify(publicKey, hashAlgorithm, hash, signature); 
}

