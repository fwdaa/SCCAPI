#include "..\stdafx.h"
#include "..\Provider.h"
#include "..\Cipher\GOST28147.h"
#include "RFC4357.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RFC4357.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа ГОСТ 28147-89 
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::CryptoPro::Wrap::RFC4357::Wrap(
	IRand^ rand, ISecretKey^ KEK, ISecretKey^ CEK)
{$
	// выполнить преобразование типа
	CryptoPro::Provider^ provider = (CryptoPro::Provider^)Provider; 

    // для специального случая
    if (ukm->Length == SEANCE_VECTOR_LEN && dynamic_cast<CAPI::CSP::SecretKey^>(CEK) != nullptr) 
	{ 
		// описатель ключа шифрования ключа
		Using<CAPI::CSP::KeyHandle^> hKEK;
    
        // при родном ключе шифрования ключа
        if (dynamic_cast<CAPI::CSP::SecretKey^>(KEK) != nullptr)
        {
	        // извлечь описатель ключа шифрования ключа 
	        hKEK.Attach(CAPI::CSP::Handle::AddRef(((CAPI::CSP::SecretKey^)KEK)->Handle)); 
        }
        // при наличии значения ключа шифрования ключа
        else if (KEK->Value != nullptr)
        {
			// получить тип ключа
			CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(
				KEK->KeyFactory, KEK->Value->Length
			); 
            // создать описатель ключа шифрования ключа
            hKEK.Attach(keyType->ConstructKey(Context, KEK->Value, 0));  
        }
        // при ошибке выбросить исключение
        else throw gcnew InvalidKeyException();  

		// установить идентификатор таблицы подстановок
		hKEK.Get()->SetString(KP_CIPHEROID, sboxOID, 0); 

        // зашифровать ключ шифрования данных
        return WrapKey(AlgID, ukm, hKEK.Get(), ((CAPI::CSP::SecretKey^)CEK)->Handle);  
    }
    else { 
		// выделить память для стартового значения хэширования
		array<BYTE>^ start = gcnew array<BYTE>(SEANCE_VECTOR_LEN); 

		// извлечь стартовое значение хэширования
		Array::Copy(ukm, 0, start, 0, start->Length);

        // создать алгоритм диверсификации ключа
        Using<CAPI::KeyDerive^> keyDerive(GetKDFAlgorithm(Context)); 

        // выполнить диверсификацию ключа
        Using<ISecretKey^> deriveKEK(keyDerive.Get()->DeriveKey(KEK, ukm, KeyFactory, 32));

        // описатель ключа шифрования данных 
        Using<CAPI::CSP::KeyHandle^> hDeriveKEK; 

        // при родном ключе шифрования ключа
        if (dynamic_cast<CAPI::CSP::SecretKey^>(deriveKEK.Get()) != nullptr)
        {
            // извлечь описатель ключа шифрования ключа 
            hDeriveKEK.Attach(CAPI::CSP::Handle::AddRef(
				((CAPI::CSP::SecretKey^)deriveKEK.Get())->Handle
			)); 
	    }
        // при наличии значения ключа шифрования ключа
        else if (deriveKEK.Get()->Value != nullptr)
        {
			// получить тип ключа
			CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(KeyFactory, 32); 

            // создать описатель ключа шифрования ключа
            hDeriveKEK.Attach(keyType->ConstructKey(Context, deriveKEK.Get()->Value, 0));  
        }
        // при ошибке выбросить исключение
        else throw gcnew InvalidKeyException();  

	    // установить параметры алгоритма шифрования
		hDeriveKEK.Get()->SetLong  (KP_MODE     , CRYPT_MODE_ECB, 0); 
		hDeriveKEK.Get()->SetLong  (KP_PADDING  , ZERO_PADDING  , 0); 
		hDeriveKEK.Get()->SetString(KP_CIPHEROID, sboxOID       , 0); 

		// создать алгоритм выработки имитовставки
		Using<CAPI::CSP::HashHandle^> hHash(Context->CreateHash(
			CALG_G28147_MAC, hDeriveKEK.Get(), 0
		)); 
		// установить стартовое значение
		hHash.Get()->SetParam(HP_HASHSTARTVECT, start, 0); 

		// вычислить значение имитовставки
		hHash.Get()->HashData(CEK->Value, 0, CEK->Length, 0); 

		// получить значение имитовставки
		array<BYTE>^ mac = hHash.Get()->GetParam(HP_HASHVAL, 0);

		// проверить корректность размера
		if (mac->Length != EXPORT_IMIT_SIZE) throw gcnew InvalidOperationException(); 

		// выделить память для результата
		array<BYTE>^ wrapped = gcnew array<BYTE>(CEK->Length + EXPORT_IMIT_SIZE); 

		// зашифровать ключ шифрования данных
		hDeriveKEK.Get()->Encrypt(CEK->Value, 0, CEK->Length, TRUE, 0, wrapped, 0); 

		// скопировать значение имитовставки
		Array::Copy(mac, 0, wrapped, CEK->Length, mac->Length); return wrapped; 
    }
}

Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::CSP::CryptoPro::Wrap::RFC4357::Unwrap(
	ISecretKey^ KEK, array<BYTE>^ wrapped, SecretKeyFactory^ keyFactory)
{$
	// выполнить преобразование типа
	CryptoPro::Provider^ provider = (CryptoPro::Provider^)Provider; 

	// определить размер ключа
	int keySize = wrapped->Length - EXPORT_IMIT_SIZE; 

    // проверить допустимость размера
    if (keySize != 32 && keySize != 64) throw gcnew NotSupportedException(); 

    // для специального случая
    if (ukm->Length == SEANCE_VECTOR_LEN) 
	{ 
		// описатель ключа шифрования ключа
		Using<CAPI::CSP::KeyHandle^> hKEK;

	    // при родном ключе шифрования ключа
	    if (dynamic_cast<CAPI::CSP::SecretKey^>(KEK) != nullptr)
	    {
		    // извлечь описатель ключа шифрования ключа 
		    hKEK.Attach(CAPI::CSP::Handle::AddRef(((CAPI::CSP::SecretKey^)KEK)->Handle)); 
	    }
        // при наличии значения ключа шифрования ключа
        else if (KEK->Value != nullptr)
        {
			// получить тип ключа
			CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(
				KEK->KeyFactory, KEK->Value->Length
			); 
            // создать описатель ключа шифрования ключа
            hKEK.Attach(keyType->ConstructKey(Context, KEK->Value, 0));  
        }
        // при ошибке выбросить исключение
        else throw gcnew InvalidKeyException();  

		// установить идентификатор таблицы подстановок
		hKEK.Get()->SetString(KP_CIPHEROID, sboxOID, 0); 

        // расшифровать ключ шифрования данных
		Using<CAPI::CSP::KeyHandle^> hCEK(UnwrapKey(Context, AlgID, ukm, hKEK.Get(), wrapped)); 

		// вернуть расшифрованный ключ
		return gcnew CAPI::CSP::SecretKey(provider, keyFactory, hCEK.Get());  
	}
    else {  
		// выделить память для стартового значения хэширования
		array<BYTE>^ start = gcnew array<BYTE>(SEANCE_VECTOR_LEN); 

		// извлечь стартовое значение хэширования
		Array::Copy(ukm, 0, start, 0, start->Length);

        // создать алгоритм диверсификации ключа
        Using<CAPI::KeyDerive^> keyDerive(GetKDFAlgorithm(Context)); 

        // выполнить диверсификацию ключа
        Using<ISecretKey^> deriveKEK(keyDerive.Get()->DeriveKey(KEK, ukm, KeyFactory, 32));

        // описатель ключа шифрования данных 
        Using<CAPI::CSP::KeyHandle^> hDeriveKEK; 

        // при родном ключе шифрования ключа
        if (dynamic_cast<CAPI::CSP::SecretKey^>(deriveKEK.Get()) != nullptr)
        {
            // извлечь описатель ключа шифрования ключа 
            hDeriveKEK.Attach(CAPI::CSP::Handle::AddRef(
				((CAPI::CSP::SecretKey^)deriveKEK.Get())->Handle
			)); 
        }
        // при наличии значения ключа шифрования ключа
        else if (deriveKEK.Get()->Value != nullptr)
        {
			// получить тип ключа
			CAPI::CSP::SecretKeyType^ keyType = provider->GetSecretKeyType(KeyFactory, 32); 

            // создать описатель ключа шифрования ключа
            hDeriveKEK.Attach(keyType->ConstructKey(Context, deriveKEK.Get()->Value, 0));  
        }
        // при ошибке выбросить исключение
        else throw gcnew InvalidKeyException();

	    // установить параметры алгоритма шифрования
	    hDeriveKEK.Get()->SetLong  (KP_MODE     , CRYPT_MODE_ECB, 0); 
	    hDeriveKEK.Get()->SetLong  (KP_PADDING  , ZERO_PADDING  , 0); 
	    hDeriveKEK.Get()->SetString(KP_CIPHEROID, sboxOID       , 0); 

		// выделить память для ключа шифрования данных
		array<BYTE>^ value = gcnew array<BYTE>(keySize); 

	    // расшифровать ключ шифрования данных
	    hDeriveKEK.Get()->Decrypt(wrapped, 0, value->Length, TRUE, 0, value, 0); 

		// создать алгоритм выработки имитовставки
		Using<CAPI::CSP::HashHandle^> hHash(
			Context->CreateHash(CALG_G28147_MAC, hDeriveKEK.Get(), 0)
		); 
		// установить стартовое значение
		hHash.Get()->SetParam(HP_HASHSTARTVECT, start, 0); 

		// вычислить значение имитовставки
		hHash.Get()->HashData(value, 0, value->Length, 0); 

		// получить значение имитовставки
		array<BYTE>^ mac = hHash.Get()->GetParam(HP_HASHVAL, 0);

		// проверить корректность размера
		if (mac->Length != EXPORT_IMIT_SIZE) throw gcnew InvalidOperationException(); 

		// проверить совпадение имитовставок
		if (!Arrays::Equals(mac, 0, wrapped, value->Length, mac->Length)) 
		{
		    // при ошибке выбросить исключение
			throw gcnew InvalidDataException(); 
		}
		// вернуть вычисленный ключ
		return keyFactory->Create(value);
    }
}

///////////////////////////////////////////////////////////////////////////////
// Шифрование ключа
///////////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::CryptoPro::Wrap::RFC4357::WrapKey(ALG_ID algID, 
	array<BYTE>^ ukm, CAPI::CSP::KeyHandle^ hKEK, CAPI::CSP::KeyHandle^ hCEK)
{$
	// проверить размер синхропосылки
	if (ukm->Length != SEANCE_VECTOR_LEN) throw gcnew NotSupportedException(); 

	// установить алгоритм экспорта и вектор инициализации
	hKEK->SetLong(KP_ALGID, algID, 0); hKEK->SetParam(KP_IV, ukm, 0);

	// определить размер буфера
	DWORD cbBlob = hCEK->Export(hKEK, SIMPLEBLOB, 0, IntPtr::Zero, 0); 

	// выделить память для структуры экспорта
	std::vector<BYTE> vecBlob(cbBlob); int keySize = hCEK->GetLong(KP_KEYLEN, 0) / 8;

	// экспортировать ключ 
	cbBlob = hCEK->Export(hKEK, SIMPLEBLOB, 0, IntPtr(&vecBlob[0]), cbBlob); 

	// выделить память для результата
	array<BYTE>^ wrapped = gcnew array<BYTE>(keySize + EXPORT_IMIT_SIZE); 
	
	// выполнить преобразование типа
	if (keySize == 32) { PCRYPT_SIMPLEBLOB pBlob = (PCRYPT_SIMPLEBLOB)&vecBlob[0];

		// вернуть зашифрованный ключ
		Marshal::Copy(IntPtr(pBlob->bEncryptedKey), wrapped, 0, keySize); 

		// вернуть имитовставку
		Marshal::Copy(IntPtr(pBlob->bMacKey), wrapped, keySize, EXPORT_IMIT_SIZE); 
	}
	else if (keySize == 64)
	{
		// выполнить преобразование типа
		PCRYPT_SIMPLEBLOB_512 pBlob = (PCRYPT_SIMPLEBLOB_512)&vecBlob[0];

		// вернуть зашифрованный ключ
		Marshal::Copy(IntPtr(pBlob->bEncryptedKey), wrapped, 0, keySize); 

		// вернуть имитовставку
		Marshal::Copy(IntPtr(pBlob->bMacKey), wrapped, keySize, EXPORT_IMIT_SIZE); 
	}
	// при ошибке выбросить исключение
	else throw gcnew NotSupportedException(); return wrapped; 
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::CryptoPro::Wrap::RFC4357::UnwrapKey(
	CAPI::CSP::ContextHandle^ hContext, ALG_ID algID, array<BYTE>^ ukm, 
	CAPI::CSP::KeyHandle^ hKEK, array<BYTE>^ wrapped)
{$
	// определить размер ключа
	int keySize = wrapped->Length - EXPORT_IMIT_SIZE; 

	// проверить размер ключа
	if (keySize != 32 && keySize != 64) throw gcnew InvalidDataException();

	// установить алгоритм импорта и вектор инициализации
	hKEK->SetLong(KP_ALGID, algID, 0); hKEK->SetParam(KP_IV, ukm, 0);

	// закодировать идентификаторы таблицы подстановок
	array<ASN1::ObjectIdentifier^>^ oids = gcnew array<ASN1::ObjectIdentifier^>(1); 
	
	// закодировать идентификатор таблицы подстановок
	oids[0] = gcnew ASN1::ObjectIdentifier(hKEK->GetString(KP_CIPHEROID, 0)); 

	// получить закодированное представление
	array<BYTE>^ encoded = ASN1::Sequence<ASN1::ObjectIdentifier^>(oids).Encoded; 

	// в зависимости от размера ключа
	if (keySize == 32)
	{
		// задать фиксированный заголовок
		BLOBHEADER blobHeader = { SIMPLEBLOB, BLOB_VERSION, 0, CALG_G28147 } ; 

		// задать заголовок КриптоПро
		CRYPT_SIMPLEBLOB_HEADER header = { blobHeader, G28147_MAGIC, algID }; 

		// определить размер структуры для импорта
		DWORD cbBlob = FIELD_OFFSET(CRYPT_SIMPLEBLOB, bEncryptionParamSet) + encoded->Length; 
		
		// выделить память для структуры импорта
		std::vector<BYTE> vecBlob(cbBlob); PCRYPT_SIMPLEBLOB pBlob = (PCRYPT_SIMPLEBLOB)&vecBlob[0]; 
		
		// скопировать заголовок и случайные данные
		pBlob->tSimpleBlobHeader = header; Marshal::Copy(ukm, 0, IntPtr(pBlob->bSV), ukm->Length);

		// скопировать зашифрованный ключ
		Marshal::Copy(wrapped, 0, IntPtr(pBlob->bEncryptedKey), keySize); 

		// скопировать имитовставку
		Marshal::Copy(wrapped, keySize, IntPtr(pBlob->bMacKey), EXPORT_IMIT_SIZE); 

		// скопировать закодированный идентификатор
		Marshal::Copy(encoded, 0, IntPtr(pBlob->bEncryptionParamSet), encoded->Length); 

		// импортировать ключ
		return hContext->ImportKey(hKEK, IntPtr(pBlob), cbBlob, CRYPT_EXPORTABLE); 
	}
	else {
		// задать фиксированный заголовок
		BLOBHEADER blobHeader = { SIMPLEBLOB, BLOB_VERSION, 0, CALG_SYMMETRIC_512 } ; 

		// задать заголовок КриптоПро
		CRYPT_SIMPLEBLOB_HEADER header = { blobHeader, G28147_MAGIC, algID }; 

		// определить размер структуры для импорта
		DWORD cbBlob = FIELD_OFFSET(CRYPT_SIMPLEBLOB_512, bEncryptionParamSet) + encoded->Length; 
		
		// выделить память для структуры импорта
		std::vector<BYTE> vecBlob(cbBlob); PCRYPT_SIMPLEBLOB_512 pBlob = (PCRYPT_SIMPLEBLOB_512)&vecBlob[0]; 
		
		// скопировать заголовок
		pBlob->tSimpleBlobHeader = header; Marshal::Copy(ukm, 0, IntPtr(pBlob->bSV), ukm->Length);

		// скопировать зашифрованный ключ
		Marshal::Copy(wrapped, 0, IntPtr(pBlob->bEncryptedKey), keySize); 

		// скопировать имитовставку
		Marshal::Copy(wrapped, keySize, IntPtr(pBlob->bMacKey), EXPORT_IMIT_SIZE); 

		// скопировать закодированный идентификатор
		Marshal::Copy(encoded, 0, IntPtr(pBlob->bEncryptionParamSet), encoded->Length); 

		// импортировать ключ
		return hContext->ImportKey(hKEK, IntPtr(pBlob), cbBlob, CRYPT_EXPORTABLE); 
	}
}
