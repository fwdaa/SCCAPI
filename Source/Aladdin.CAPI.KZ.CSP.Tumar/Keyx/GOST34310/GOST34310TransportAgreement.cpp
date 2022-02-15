#include "..\..\stdafx.h"
#include "..\..\Container.h"
#include "GOST34310TransportAgreement.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310TransportAgreement.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм согласования ключа
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::TransportAgreementData^ Aladdin::CAPI::KZ::CSP::Tumar::Keyx::GOST34310::TransportAgreement::Wrap(
	IPrivateKey^ privateKey, IPublicKey^ publicKey, 
	array<IPublicKey^>^ recipientPublicKeys, IRand^ rand, ISecretKey^ CEK)
{$
	// преобразовать тип ключа
	CAPI::CSP::PrivateKey^ cspPrivateKey = (CAPI::CSP::PrivateKey^)privateKey; 

	// проверить тип ключа
	if (cspPrivateKey->KeyType != AT_KEYEXCHANGE) throw gcnew InvalidKeyException(); 

	// проверить допустимость операции
	if (privateKey->Container == nullptr) throw gcnew InvalidKeyException();

    // преобразовать тип контейнера
    Container^ container = (Container^)privateKey->Container; 

	// при наличии родного ключа
	Using<CAPI::CSP::KeyHandle^> hCEK; if (dynamic_cast<CAPI::CSP::SecretKey^>(CEK) != nullptr)
	{
		// извлечь описатель ключа
		hCEK.Attach(CAPI::CSP::Handle::AddRef(((CAPI::CSP::SecretKey^)CEK)->Handle)); 
	}
	// при наличии значения ключа
	else if (CEK->Value != nullptr)
	{
		// получить тип ключа
		CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(
			CEK->KeyFactory, CEK->Value->Length
		); 
		// создать ключ для алгоритма
		hCEK.Attach(keyType->ConstructKey(container->Handle, CEK->Value, CRYPT_EXPORTABLE));  
	}
	// при ошибке выбросить исключение
	else throw gcnew InvalidKeyException();  

	// переустановить активный ключ
	Container::SetActivePrivateKey active(container, cspPrivateKey); 

	// выделить буфер требуемого размера
	array<array<BYTE>^>^ encryptedKeys = gcnew array<array<BYTE>^>(recipientPublicKeys->Length); 

	// для всех получателей
	for (int i = 0; i < encryptedKeys->Length; i++)
	{
		// импортировать открытый ключ
		Using<CAPI::CSP::KeyHandle^> hPublicKey(provider->ImportPublicKey(
			container->Handle, recipientPublicKeys[i], cspPrivateKey->KeyType
		));  
		// получить способ экспорта
		DWORD keyMix = container->Handle->GetLong(PP_KEYMIX, 0);

		// указать способ экспорта
		container->Handle->SetLong(PP_KEYMIX, 1, 0); 
		try { 				 
			// экспортировать ключ
			encryptedKeys[i] = container->ExportKey(hCEK.Get(), hPublicKey.Get(), SIMPLEBLOB, flags);	
		}
		// восстановить способ экспорта
		finally { container->Handle->SetLong(PP_KEYMIX, keyMix, 0); }
	}
	// вернуть зашифрованные ключи
	return gcnew TransportAgreementData(publicKey, nullptr, encryptedKeys); 
}

Aladdin::CAPI::ISecretKey^ 
Aladdin::CAPI::KZ::CSP::Tumar::Keyx::GOST34310::TransportAgreement::Unwrap(
	IPrivateKey^ recipientPrivateKey, IPublicKey^ publicKey, 
	array<BYTE>^ random, array<BYTE>^ encryptedKey, SecretKeyFactory^ keyFactory)
{$
	// преобразовать тип ключа
	CAPI::CSP::PrivateKey^ cspPrivateKey = (CAPI::CSP::PrivateKey^)recipientPrivateKey; 

	// проверить тип ключа
	if (cspPrivateKey->KeyType != AT_KEYEXCHANGE) throw gcnew InvalidKeyException(); 

	// проверить допустимость операции
	if (cspPrivateKey->Container == nullptr) throw gcnew InvalidKeyException();

    // преобразовать тип контейнера
    Container^ container = (Container^)cspPrivateKey->Container; 

	// получить адрес буфера
	pin_ptr<BYTE> ptrBlob = &encryptedKey[0]; DWORD cbBlob = encryptedKey->Length; 
	
	// переустановить активный ключ
	Container::SetActivePrivateKey active(container, cspPrivateKey); 

	// импортировать открытый ключ
	Using<CAPI::CSP::KeyHandle^> hPublicKey(provider->ImportPublicKey(
		container->Handle, publicKey, cspPrivateKey->KeyType
	));  
	// получить способ импорта
	DWORD keyMix = container->Handle->GetLong(PP_KEYMIX, 0);

	// указать способ импорта
	container->Handle->SetLong(PP_KEYMIX, 1, 0); 
	try {
		// импортировать ключ
		Using<CAPI::CSP::KeyHandle^> hCEK(container->ImportKey(
			hPublicKey.Get(), IntPtr(ptrBlob), cbBlob, flags | CRYPT_EXPORTABLE
		)); 
		// получить тип ключа
		CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(keyFactory, 32); 

		// изменить контекст ключа
		return keyFactory->Create(keyType->GetKeyValue(container->Handle, hCEK.Get()));
	}
	// восстановить способ импорта
	finally { container->Handle->SetLong(PP_KEYMIX, keyMix, 0); }
}

