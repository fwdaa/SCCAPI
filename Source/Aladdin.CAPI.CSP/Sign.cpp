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
array<BYTE>^ Aladdin::CAPI::CSP::SignHash::Sign(IPrivateKey^ privateKey, 
	IRand^ rand, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// проверить наличие контейнера
	if (privateKey->Container == nullptr) throw gcnew InvalidOperationException();

	// получить контейнер ключа
	Container^ container = (Container^)(privateKey->Container);  

	// создать алгоритм хэширования
	Using<HashHandle^> hHash(CreateHash(container->Handle, hashAlgorithm));

	// определить тип ключа
	DWORD keyType = ((PrivateKey^)privateKey)->KeyType; 

	// установить хэш-значение 
	hHash.Get()->SetParam(HP_HASHVAL, hash, 0); 

	// подписать хэш-значение
	return container->SignHash(keyType, hHash.Get(), flags);
}

void Aladdin::CAPI::CSP::VerifyHash::Verify(IPublicKey^ publicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// импортировать открытый ключ подписи
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, publicKey, AT_SIGNATURE
	)); 
	// создать алгоритм хэширования
	Using<HashHandle^> hHash(CreateHash(provider->Handle, hashAlgorithm));

	// установить хэш-значение 
	hHash.Get()->SetParam(HP_HASHVAL, hash, 0); 

	// проверить подпись данных
	hPublicKey.Get()->VerifySignature(hHash.Get(), signature, flags); 
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм выработки подписи данных
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::SignData::Init(IPrivateKey^ privateKey, IRand^ rand)
{$
	hHash.Close(); 

	// проверить наличие контейнера
	if (privateKey->Container == nullptr) throw gcnew InvalidOperationException();

	// вызвать базовую функцию
	CAPI::SignData::Init(privateKey, rand); 

	// получить контейнер ключа
	Container^ container = (Container^)(privateKey->Container); 

	// создать алгоритм хэширования
	hHash.Attach(CreateHash(container->Handle, privateKey->Parameters));
}
				
void Aladdin::CAPI::CSP::SignData::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// захэшировать данные
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0);  
}

array<BYTE>^ Aladdin::CAPI::CSP::SignData::Finish(IRand^ rand)
{$
	// получить контейнер ключа
	Container^ container = (Container^)(PrivateKey->Container);  

	// определить тип ключа
	DWORD keyType = ((CSP::PrivateKey^)PrivateKey)->KeyType; 

	// подписать хэш-значение
	array<BYTE>^ signature = container->SignHash(keyType, hHash.Get(), flags);

	// вернуть подпись
	hHash.Close(); CAPI::SignData::Finish(rand); return signature; 
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи данных
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::VerifyData::Init(IPublicKey^ publicKey, array<BYTE>^ signature)
{$
    // вызвать базовую функцию
	CAPI::VerifyData::Init(publicKey, signature); hHash.Close(); 

	// создать алгоритм хэширования
	hHash.Attach(CreateHash(provider->Handle, publicKey->Parameters));
}
				
void Aladdin::CAPI::CSP::VerifyData::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// захэшировать данные
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0);  
}

void Aladdin::CAPI::CSP::VerifyData::Finish()
{$
	// импортировать открытый ключ подписи
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, PublicKey, AT_SIGNATURE
	)); 
	// проверить подпись данных
	try { hPublicKey.Get()->VerifySignature(hHash.Get(), Signature, flags); }

	// освободить выделенные ресурсы
	finally { hHash.Close(); }
}
