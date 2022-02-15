#include "stdafx.h" 
#include "Keyx.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Keyx.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Ассиметричный алгоритм шифрования
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::BEncipherment::Encrypt( 
	IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data)
{$
	// создать объект открытого ключа
	Using<BKeyHandle^> hPublicKey(ImportPublicKey(hProvider.Get(), publicKey));
 
	// зашифровать данные
	return Encrypt(hPublicKey.Get(), data);  
}

array<BYTE>^ Aladdin::CAPI::CNG::BDecipherment::Decrypt(
	IPrivateKey^ privateKey, array<BYTE>^ data)
{$
	// импортировать личный ключ
	Using<BKeyHandle^> hPrivateKey(ImportPrivateKey(hProvider.Get(), privateKey));

	// расшифровать данные
	return Decrypt(hPrivateKey.Get(), data); 
}

array<BYTE>^ Aladdin::CAPI::CNG::NEncipherment::Encrypt( 
	IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data)
{$
	// создать объект открытого ключа
	Using<NKeyHandle^> hPublicKey(provider->ImportPublicKey(AT_KEYEXCHANGE, publicKey));
 
	// зашифровать данные
	return Encrypt(hPublicKey.Get(), data); 
}

array<BYTE>^ Aladdin::CAPI::CNG::NDecipherment::Decrypt(
	IPrivateKey^ privateKey, array<BYTE>^ data)
{$
	// получить описатель личного ключа
	NKeyHandle^ hPrivateKey = ((NPrivateKey^)privateKey)->Handle;

	// расшифровать данные
	return Decrypt(privateKey->Scope, hPrivateKey, data); 
}

array<BYTE>^ Aladdin::CAPI::CNG::NDecipherment::Decrypt(SecurityObject^ scope, 
	NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// для ключа контейнера
	if (dynamic_cast<Container^>(scope) != nullptr) 
	{
		// преобразовать тип контейнера
		Container^ container = (Container^)scope; 

		// расшифровать данные
		return container->Decrypt(hPrivateKey, padding, data, flags); 
	}
	// расшифровать данные
	else return hPrivateKey->Decrypt(padding, data, flags);
}

