#include "stdafx.h"
#include "Derive.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Derive.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::CNG::BKeyAgreement::DeriveKey(	    
	IPrivateKey^ privateKey, IPublicKey^ publicKey, 
	array<BYTE>^ random, SecretKeyFactory^ keyType, int keySize)
{$
	// определить имя алгоритма
	String^ algName = GetName(privateKey->Parameters); 

	// создать криптографический контекст
	Using<BProviderHandle^> hProvider(gcnew BProviderHandle(provider, algName, 0)); 

	// импортировать личный ключ
	Using<BKeyHandle^> hPrivateKey(ImportPrivateKey(hProvider.Get(), algName, privateKey));

	// импортировать открытый ключ
	Using<BKeyHandle^> hPublicKey(ImportPublicKey(hProvider.Get(), algName, publicKey));

	// выполнить разделение секрета
	Using<BSecretHandle^> hSecret(AgreementSecret(hPrivateKey.Get(), hPublicKey.Get()));

	// выполнить согласование общего ключа
	return keyType->Create(DeriveKey(privateKey->Parameters, hSecret.Get(), random, keySize));  
}

Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::CNG::NKeyAgreement::DeriveKey(	    
	IPrivateKey^ privateKey, IPublicKey^ publicKey, 
	array<BYTE>^ random, SecretKeyFactory^ keyFactory, int keySize)
{$
	// получить описатель личного ключа
	NKeyHandle^ hPrivateKey = ((NPrivateKey^)privateKey)->Handle;

	// получить используемый провайдер
	NProvider^ provider = (NProvider^)privateKey->Factory; 

	// импортировать открытый ключ подписи
	Using<NKeyHandle^> hPublicKey(provider->ImportPublicKey(AT_KEYEXCHANGE, publicKey));

	// выполнить разделение секрета
	Using<CAPI::CNG::NSecretHandle^> hSecret(AgreementSecret(
		privateKey->Scope, hPrivateKey, hPublicKey.Get()
	));
	// выполнить согласование общего ключа
	return keyFactory->Create(DeriveKey(privateKey->Parameters, hSecret.Get(), random, keySize)); 
}

Aladdin::CAPI::CNG::NSecretHandle^ Aladdin::CAPI::CNG::NKeyAgreement::AgreementSecret(
	SecurityObject^ scope, NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey, DWORD flags)
{$
	// для ключа контейнера
	if (dynamic_cast<Container^>(scope) != nullptr) 
	{
		// преобразовать тип контейнера
		Container^ container = (Container^)scope; 

		// согласовать общий ключ
		return container->AgreementSecret(hPrivateKey, hPublicKey, flags); 
	}
	// согласовать общий ключ
	else return hPrivateKey->AgreementSecret(hPublicKey, flags);
}

