#include "stdafx.h"
#include "Sign.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Sign.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи хэш-значения
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::BSignHash::Sign(IPrivateKey^ privateKey, 
	IRand^ rand, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// определить имя алгоритма
	String^ algName = GetName(privateKey->Parameters); 

	// создать криптографический контекст
	Using<BProviderHandle^> hProvider(gcnew BProviderHandle(provider, algName, 0)); 

	// импортировать личный ключ подписи
	Using<BKeyHandle^> hPrivateKey(ImportPrivateKey(hProvider.Get(), algName, privateKey));
     
	// подписать хэш-значение
	return Sign(privateKey->Parameters, hPrivateKey.Get(), hashAlgorithm, hash);  
}

void Aladdin::CAPI::CNG::BVerifyHash::Verify(IPublicKey^ publicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// определить имя алгоритма
	String^ algName = GetName(publicKey->Parameters); 

	// создать криптографический контекст
	Using<BProviderHandle^> hProvider(gcnew BProviderHandle(provider, algName, 0)); 
    
    // импортировать открытый ключ подписи
    Using<BKeyHandle^> hPublicKey(ImportPublicKey(hProvider.Get(), algName, publicKey));

    // проверить подпись данных
    Verify(publicKey->Parameters, hPublicKey.Get(), hashAlgorithm, hash, signature);
}

array<BYTE>^ Aladdin::CAPI::CNG::NSignHash::Sign(IPrivateKey^ privateKey, 
	IRand^ rand, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// получить описатель личного ключа
	NKeyHandle^ hPrivateKey = ((NPrivateKey^)privateKey)->Handle;

	// подписать хэш-значение
	return Sign(privateKey->Scope, privateKey->Parameters, hPrivateKey, hashAlgorithm, hash);
}

array<BYTE>^ Aladdin::CAPI::CNG::NSignHash::Sign(SecurityObject^ scope,
	NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ hash, DWORD flags) 
{$
	// для ключа контейнера
	if (dynamic_cast<Container^>(scope) != nullptr) 
	{
		// преобразовать тип контейнера
		Container^ container = (Container^)scope; 

		// подписать хэш-значение
		return container->SignHash(hPrivateKey, padding, hash, flags); 
	}
	// подписать хэш-значение
	else return hPrivateKey->SignHash(padding, hash, flags);
}

void Aladdin::CAPI::CNG::NVerifyHash::Verify(IPublicKey^ publicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// импортировать открытый ключ подписи
	Using<NKeyHandle^> hPublicKey(provider->ImportPublicKey(AT_SIGNATURE, publicKey));
 
	// проверить подпись данных
	Verify(publicKey->Parameters, hPublicKey.Get(), hashAlgorithm, hash, signature); 
}
