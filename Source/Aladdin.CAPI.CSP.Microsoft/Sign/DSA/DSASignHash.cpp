#include "..\..\stdafx.h"
#include "DSASignHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSASignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения DSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::CSP::Microsoft::Sign::DSA::SignHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// определить идентификатор алгоритма хэширования
	String^ hashOID = hashAlgorithm->Algorithm->Value; 

	// проверить идентификатор алгоритма хэширования
	if (hashOID != ASN1::ANSI::OID::ssig_sha1) throw gcnew NotSupportedException();

	// создать алгоритм хэширования
	return hContext->CreateHash(CALG_SHA1, nullptr, 0); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Microsoft::Sign::DSA::SignHash::Sign(
	IPrivateKey^ privateKey, IRand^ rand, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// подписать хэш-значение
	array<BYTE>^ signature = CAPI::CSP::SignHash::Sign(privateKey, rand, hashAlgorithm, hash); 

	// определить параметр алгоритма
	int bytesR = ((ANSI::X957::IParameters^)privateKey->Parameters)->Q->BitLength / 8; 

	// проверить размер подписи
	if (signature->Length <= bytesR) throw gcnew InvalidDataException();

	// определить размер параметра S
	int bytesS = signature->Length - bytesR; 

	// раскодировать параметры R и S
	Math::BigInteger^ R = Math::Convert::ToBigInteger(signature,      0, bytesR, Endian); 
	Math::BigInteger^ S = Math::Convert::ToBigInteger(signature, bytesR, bytesS, Endian); 

	// закодировать подпись
	return Aladdin::ASN1::ANSI::X957::DssSigValue(
		gcnew Aladdin::ASN1::Integer(R), gcnew Aladdin::ASN1::Integer(S)).Encoded; 
}
