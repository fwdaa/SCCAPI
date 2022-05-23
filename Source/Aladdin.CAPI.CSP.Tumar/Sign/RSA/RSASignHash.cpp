#include "..\..\stdafx.h"
#include "..\..\Container.h"
#include "RSASignHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSASignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения RSA
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::Tumar::Sign::RSA::SignHash::Sign(
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
	return Microsoft::Sign::RSA::SignHash::Sign(privateKey, rand, hashAlgorithm, hash); 
}
