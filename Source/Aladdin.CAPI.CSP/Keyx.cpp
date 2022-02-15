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
array<BYTE>^ Aladdin::CAPI::CSP::Encipherment::Encrypt( 
	IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data)
{$
	// импортировать открытый ключ
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, publicKey, AT_KEYEXCHANGE
	));  
	// зашифровать данные
	return hPublicKey.Get()->Encrypt(data, flags); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Decipherment::Decrypt(
	IPrivateKey^ privateKey, array<BYTE>^ data)
{$
	// получить описатель личного ключа
	Using<KeyHandle^> hPrivateKey(((PrivateKey^)privateKey)->OpenHandle());

	// для ключа из контейнера
	if (privateKey->Container != nullptr)
	{
		// получить контейнер ключа
		Container^ container = (Container^)(privateKey->Container);  
 
		// расшифровать данные
		return container->Decrypt(hPrivateKey.Get(), data, flags); 
	}
	// расшифровать данные
	else return hPrivateKey.Get()->Decrypt(data, flags);
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм согласования ключа
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::CSP::KeyAgreement::DeriveKey(
	IPrivateKey^ privateKey, IPublicKey^ publicKey, 
	array<BYTE>^ random, SecretKeyFactory^ keyFactory, int keySize)
{$
	// импортировать открытый ключ
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, publicKey, AT_KEYEXCHANGE
	));
	// определить размер буфера
	DWORD cbBlob = hPublicKey.Get()->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0);

	// выделить память для структуры экспорта
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// экспортировать открытый ключ
	cbBlob = hPublicKey.Get()->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr(ptrBlob), cbBlob);

	// получить описатель личного ключа
	Using<KeyHandle^> hPrivateKey(((PrivateKey^)privateKey)->OpenHandle()); 

	// для ключа из контейнера 
	if (privateKey->Container != nullptr)
	{
		// получить контейнер для личного ключа
		Container^ container = (Container^)(privateKey->Container); 

		// согласовать ключ
		Using<KeyHandle^> hKey(container->ImportKey(
			hPrivateKey.Get(), IntPtr(ptrBlob), cbBlob, flags | CRYPT_EXPORTABLE
		)); 
		// установить параметры ключа
		SetKeyParameters(container->Handle, hKey.Get(), random, keySize); 

		// при совпадении контекста
		if (container->Handle->Value == provider->Handle->Value) 
		{
			// вернуть объект ключа
			return gcnew SecretKey(provider, keyFactory, hKey.Get());
		}
		// получить тип ключа
		SecretKeyType^ keyType = provider->GetSecretKeyType(keyFactory, keySize); 

		// вернуть значение ключа
		return keyFactory->Create(keyType->GetKeyValue(container->Handle, hKey.Get())); 
	}
	else {
		// согласовать ключ
		Using<KeyHandle^> hKey(provider->Handle->ImportKey(
			hPrivateKey.Get(), IntPtr(ptrBlob), cbBlob, flags | CRYPT_EXPORTABLE
		));
		// установить параметры ключа
		SetKeyParameters(provider->Handle, hKey.Get(), random, keySize);
 
		// вернуть согласованный ключ
		return gcnew SecretKey(provider, keyFactory, hKey.Get());  
	}
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм обмена ключа
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::TransportKeyData^ 
Aladdin::CAPI::CSP::TransportKeyWrap::Wrap(
	ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
	IPublicKey^ publicKey, IRand^ rand, ISecretKey^ CEK) 
{$
	// импортировать открытый ключ
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, publicKey, AT_KEYEXCHANGE
	));  
	// при наличии родного ключа
	Using<KeyHandle^> hCEK; if (dynamic_cast<SecretKey^>(CEK) != nullptr)
	{
		// извлечь описатель ключа
		hCEK.Attach(Handle::AddRef(((SecretKey^)CEK)->Handle)); 
	}
    // при наличии значения ключа
    else if (CEK->Value != nullptr)
    {
		// получить тип ключа
		SecretKeyType^ keyType = provider->GetSecretKeyType(
			CEK->KeyFactory, CEK->Value->Length
		); 
        // создать ключ для алгоритма
		hCEK.Attach(keyType->ConstructKey(
			hContext, CEK->Value, CRYPT_EXPORTABLE
		));
    }
    // при ошибке выбросить исключение
    else throw gcnew InvalidKeyException();  

    // определить требуемый размер буфера
    DWORD cbBlob = hCEK.Get()->Export(hPublicKey.Get(), SIMPLEBLOB, flags, IntPtr::Zero, 0); 

    // выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
    PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob;
		   
	// выполнить экспорт ключа
    cbBlob = hCEK.Get()->Export(hPublicKey.Get(), SIMPLEBLOB, flags, IntPtr(pBlob), cbBlob);

    // определить смещение зашифрованного ключа
    DWORD offsetKey = sizeof(PUBLICKEYSTRUC) + sizeof(ALG_ID);

    // выделить буфер для зашифрованного ключа
    array<BYTE>^ encryptedKey = gcnew array<BYTE>(cbBlob - offsetKey);

    // скопировать зашифрованный ключ
    Array::Copy(blob, offsetKey, encryptedKey, 0, encryptedKey->Length); 

    // вернуть зашифрованный ключ
    return gcnew TransportKeyData(algorithmParameters, encryptedKey);    
}

Aladdin::CAPI::ISecretKey^ 
Aladdin::CAPI::CSP::TransportKeyUnwrap::Unwrap(
	IPrivateKey^ privateKey, TransportKeyData^ transportData, SecretKeyFactory^ keyFactory)
{$
	// проверить наличие параметров
	if (transportData == nullptr) throw gcnew ArgumentException(); 

	// получить тип ключа
	SecretKeyType^ keyType = provider->GetSecretKeyType(keyFactory, 0); 

    // задать фиксированный заголовок
    BLOBHEADER blobHeader = { SIMPLEBLOB, CUR_BLOB_VERSION, 0, keyType->AlgID };

    // определить смещение зашифрованного ключа
    DWORD offsetKey = sizeof(PUBLICKEYSTRUC) + sizeof(ALG_ID);

    // извлечь зашифрованный ключ
    array<BYTE>^ encryptedKey = transportData->EncryptedKey;  

    // определить размер буфера для импорта
    DWORD cbBlob = offsetKey + encryptedKey->Length; 

	// выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
    PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; *pBlob = blobHeader; 

    // указать идентификатор открытого ключа
    *(ALG_ID*)(pBlob + 1) = GetPublicKeyID(privateKey->Parameters);

    // скопировать значение зашифрованного ключа
    Array::Copy(encryptedKey, 0, blob, offsetKey, encryptedKey->Length);  

	// получить описатель личного ключа
	Using<KeyHandle^> hPrivateKey(((PrivateKey^)privateKey)->OpenHandle()); 

	// для ключа из контейнера
	if (privateKey->Container != nullptr)
	{
		// преобразовать тип контейнера
		Container^ container = (Container^)(privateKey->Container); 

		// импортировать ключ
		Using<KeyHandle^> hCEK(container->ImportKey(
			hPrivateKey.Get(), IntPtr(pBlob), cbBlob, flags | CRYPT_EXPORTABLE
		));
		// вернуть значение ключа
		return keyFactory->Create(keyType->GetKeyValue(container->Handle, hCEK.Get())); 
	}
	else {
		// импортировать ключ
		Using<KeyHandle^> hCEK(provider->ImportKey(nullptr, 
			hPrivateKey.Get(), IntPtr(pBlob), cbBlob, flags | CRYPT_EXPORTABLE
		)); 
		// вернуть значение ключа
		return keyFactory->Create(keyType->GetKeyValue(provider->Handle, hCEK.Get())); 
	}
}

