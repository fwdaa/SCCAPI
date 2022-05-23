#include "..\..\stdafx.h"
#include "GOST34310VerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310VerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения ГОСТ Р 34.10-2001, 2012
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::CSP::Tumar::Sign::GOST34310::VerifyHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// получить алгоритм хэширования
	Using<IAlgorithm^> algorithm(Provider->CreateAlgorithm<CAPI::Hash^>(nullptr, hashAlgorithm)); 

	// проверить поддержку алгоритма хэширования
	if (algorithm.Get() == nullptr) throw gcnew NotSupportedException();

    // создать алгоритм хэширования
    return hContext->CreateHash(hashID, nullptr, 0); 
}

