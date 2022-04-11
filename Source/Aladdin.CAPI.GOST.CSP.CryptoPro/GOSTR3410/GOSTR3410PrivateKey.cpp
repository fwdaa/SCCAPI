#include "..\stdafx.h"
#include "..\Provider.h"
#include "GOSTR3410PrivateKey.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOSTR3410PrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Личный ключ ГОСТ P34.10
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::GOST::CSP::CryptoPro::GOSTR3410::PrivateKey::GetPrivateValue()
{$
    // преобразовать тип провайдера
    Provider^ provider = (Provider^)Factory; 

	// получить описатель провайдера
	CAPI::CSP::ContextHandle^ hContext = provider->Handle; 

	// получить описатель контейнера
    if (Container != nullptr) hContext = ((CAPI::CSP::Container^)Container)->Handle;

	// получить описатель ключа
	Using<CAPI::CSP::KeyHandle^> hKeyPair(OpenHandle()); 

	// определить идентификатор алгоритма ключа
	ALG_ID algID = (ALG_ID)hKeyPair.Get()->GetLong(KP_ALGID, 0); 

	// идентификатор алгоритма экспорта ключа
	ALG_ID exportID = provider->GetExportID(provider->ConvertKeyOID(algID)); 

	// сгенерировать ключ шифрования ключа
	Using<CAPI::CSP::KeyHandle^> hKEK(hContext->GenerateKey(CALG_G28147, CRYPT_EXPORTABLE)); 

	// получить идентификатор таблицы подстановок
	String^ sboxOID = hKEK.Get()->GetString(KP_CIPHEROID, 0);

	// указать идентификатор алгоритма
	hKEK.Get()->SetLong(KP_ALGID, exportID, 0); 

	// экспортировать личный ключ
	array<BYTE>^ blob = Export(hKEK.Get(), 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	CRYPT_PUBKEY_INFO_HEADER* pBlob = (CRYPT_PUBKEY_INFO_HEADER*)(PBYTE)ptrBlob;

	// восстановить идентификатор алгоритма
	hKEK.Get()->SetLong(KP_ALGID, CALG_G28147, 0); 

	// определить размер закодированной структуры
	DWORD cbKeyTransfer = blob->Length - sizeof(*pBlob);

	// раскодировать структуру с имитовставкой
	ASN1::GOST::CryptoProKeyTransfer^ keyTransfer = 
		gcnew ASN1::GOST::CryptoProKeyTransfer(
			ASN1::Encodable::Decode(blob, sizeof(*pBlob), cbKeyTransfer)
	); 
	// извлечь значение зашифрованного личного ключа
	ASN1::GOST::EncryptedKey^ encryptedKey = 
		keyTransfer->KeyTransferContent->EncryptedPrivateKey; 

	// извлечь значение UKM
	array<BYTE>^ ukm = keyTransfer->KeyTransferContent->SeanceVector->Value;

	// выделить общий буфер
	array<BYTE>^ wrappedCEK = Arrays::Concat(
		encryptedKey->Encrypted->Value, encryptedKey->MacKey->Value
	); 
	// создать алгоритм шифрования ключа
	Using<KeyWrap^> keyWrap(provider->CreateExportKeyWrap(hContext, exportID, sboxOID, ukm)); 

	// создать объект ключа
	CAPI::CSP::SecretKey KEK(provider, Keys::GOST::Instance, hKEK.Get()); 

	// указать тип ключа
	CAPI::SecretKeyFactory^ typeCEK = (wrappedCEK->Length == 36) ? 
		Keys::GOST::Instance : SecretKeyFactory::Generic; 

	// расшифровать значение ключа
	Using<ISecretKey^> secret(keyWrap.Get()->Unwrap(%KEK, wrappedCEK, typeCEK));
		
	// раскодировать значение
	d = Math::Convert::ToBigInteger(secret.Get()->Value, Endian); 
}

