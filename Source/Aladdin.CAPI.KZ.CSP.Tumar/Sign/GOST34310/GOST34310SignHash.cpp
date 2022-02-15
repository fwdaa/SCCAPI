#include "..\..\stdafx.h"
#include "..\..\Container.h"
#include "GOST34310SignHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310SignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения ГОСТ Р 34.10-2001, 2012
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::KZ::CSP::Tumar::Sign::GOST34310::SignHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// получить алгоритм хэширования
	Using<IAlgorithm^> algorithm(Provider->CreateAlgorithm<CAPI::Hash^>(nullptr, hashAlgorithm)); 

	// проверить поддержку алгоритма хэширования
	if (algorithm.Get() == nullptr) throw gcnew NotSupportedException();

    // создать алгоритм хэширования
    return hContext->CreateHash(hashID, nullptr, 0); 
}

array<BYTE>^ Aladdin::CAPI::KZ::CSP::Tumar::Sign::GOST34310::SignHash::Sign(
	IPrivateKey^ privateKey, IRand^ rand, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// преобразовать тип ключа
	CAPI::CSP::PrivateKey^ cspPrivateKey = (CAPI::CSP::PrivateKey^)privateKey; 

	// проверить наличие контейнера
	if (privateKey->Container == nullptr) throw gcnew InvalidKeyException();

	// получить контейнер ключа
	Container^ container = (Container^)privateKey->Container; 

	// переустановить активный ключ
	Container::SetActivePrivateKey active(container, cspPrivateKey); 

	// вызвать базовую функцию
	array<BYTE>^ signature = CAPI::CSP::SignHash::Sign(privateKey, rand, hashAlgorithm, hash); 

	// изменить порядок байтов
	Array::Reverse(signature); return signature; 
}

