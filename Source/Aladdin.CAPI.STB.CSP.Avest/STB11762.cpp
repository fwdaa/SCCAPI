#include "stdafx.h"
#include "STB11762.h"
#include "STB11761.h"
#include "GOST28147.h"
#include "BelT.h"

using namespace System::Runtime::InteropServices; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::KeyPairGenerator::Generate(
	CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11762); 	

	// получить фабрику ключей провайдера
	IKeyFactory^ provKeyFactory = ((Provider^)provider)->KeyFactory; 

	// закодировать параметры ключей провайдера
	ASN1::IEncodable^ provKeyParameters = provKeyFactory->Parameters->Encodable; 

	// закодировать параметры ключей
	ASN1::IEncodable^ keyParameters = keyFactory->Parameters->Encodable; 

	// сравнить совпадение парметров
	if (!provKeyParameters->Equals(keyParameters)) throw gcnew NotSupportedException(); 

	// создать пару ключей
	return provider->GenerateKey(container, keyType, keyFlags); 
}

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения СТБ 1176.2
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::SignHash::CreateHash(
	CAPI::CSP::ContextHandle hContext, ASN1::ISO::AlgorithmIdentifier^ hashAgorithm)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11762::SignHash::CreateHash); 

	// проверить идентификатор алгоритма
	if (hashAgorithm->Algorithm->Value == ASN1::STB::Avest::OID::bhf) 
	{
		// создать алгоритм хэширования
		return hContext.CreateHash(CALG_BHF, CAPI::CSP::KeyHandle::Zero, 0); 
	}
	// проверить идентификатор алгоритма
	if (hashAgorithm->Algorithm->Value == ASN1::STB::Avest::OID::belt_hash) 
	{
		// создать алгоритм хэширования
		return hContext.CreateHash(CALG_BELT_HASH, CAPI::CSP::KeyHandle::Zero, 0); 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::VerifyHash::CreateHash(
	CAPI::CSP::ContextHandle hContext, ASN1::ISO::AlgorithmIdentifier^ hashAgorithm)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11762::VerifyHash::CreateHash); 

	// проверить идентификатор алгоритма
	if (hashAgorithm->Algorithm->Value == ASN1::STB::Avest::OID::bhf) 
	{
		// создать алгоритм хэширования
		return hContext.CreateHash(CALG_BHF, CAPI::CSP::KeyHandle::Zero, 0); 
	}
	// проверить идентификатор алгоритма
	if (hashAgorithm->Algorithm->Value == ASN1::STB::Avest::OID::belt_hash) 
	{
		// создать алгоритм хэширования
		return hContext.CreateHash(CALG_BELT_HASH, CAPI::CSP::KeyHandle::Zero, 0); 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException(); 
}
///////////////////////////////////////////////////////////////////////
// Подпись данных СТБ 1176.2
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::SignDataSTB11761::CreateHash(
	CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::SignDataSTB11761::CreateHash); 

	// получить стартовое значение
	array<BYTE>^ start = ((Avest::STB11762::IParameters^)keyFactory->Parameters)->Sign->H; 

	// создать алгоритм хэширования
	return STB11761::Hash(Provider, hContext, start).Construct(); 
}

Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::VerifyDataSTB11761::CreateHash(
	CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::VerifyDataSTB11761::CreateHash); 

	// получить стартовое значение
	array<BYTE>^ start = ((Avest::STB11762::IParameters^)keyFactory->Parameters)->Sign->H; 

	// создать алгоритм хэширования
	return STB11761::Hash(Provider, hContext, start).Construct(); 
}
///////////////////////////////////////////////////////////////////////
// Подпись данных СТБ 1176.2
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::SignDataBelT::CreateHash(
	CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::SignDataBelT::CreateHash); 

	// создать алгоритм хэширования
	return BelT::Hash(Provider, hContext).Construct(); 
}
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::VerifyDataBelT::CreateHash(
	CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::VerifyDataBelT::CreateHash); 

	// создать алгоритм хэширования
	return BelT::Hash(Provider, hContext).Construct(); 
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм обмена СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ASN1TransportData^ Aladdin::CAPI::STB::Avest::CSP::STB11762::ASN1KeyWrap::Wrap(
	IPublicKey^ publicKey, IRand^ rand, IKey^ CEK)
{
	ATRACE_SCOPE(Aladdin::STB::Avest::CSP::STB11762::ASN1KeyWrap::Unwrap); 

	// указать идентификатор таблицы подстановок
	String^ sboxOID = ASN1::STB::Avest::OID::parameters_sboxes_default; 

	// получить параметры алгоритма
	STB::Avest::STB11762::IParameters^ parameters =
		(STB::Avest::STB11762::IParameters^)publicKey->KeyFactory->Parameters; 

	// импортировать открытый ключ обмена
	CAPI::CSP::SessionObject<CAPI::CSP::KeyHandle> sessionPubKey(
		provider->ImportPublicKey(CALG_BDH, publicKey)
	); 
	// создать алгоритм шифрования блока
	GOST28147::BlockEngine^ blockEngine = 
        gcnew GOST28147::BlockEngine(provider, provider->Handle.Context); 

	// создать ключ шифрования данных по его значению
	CAPI::CSP::SessionKey sessionCEK(provider->ConstructKey(
        provider->Handle.Context, CALG_G28147, Key::FromBinary(CEK->Value)
    )); 
	// определить размер нонки в байтах
	int cb = (parameters->KeyX->L + 7) / 8; DWORD cbBlob = sizeof(AVEST_SIMPLE_BLOB) + cb; 

	// выделить память для структуры экспорта
	PAVEST_SIMPLE_BLOB pBlob = (PAVEST_SIMPLE_BLOB)_alloca(cbBlob); 

	// экспортировать ключ шифрования данных
	cbBlob = sessionCEK.Handle.Export(sessionPubKey.Handle, SIMPLEBLOB, 0, IntPtr(pBlob), cbBlob); 

	// извлечь параметры зашифрованного ключа
	array<BYTE>^ encrypted = gcnew array<BYTE>(32); Marshal::Copy(IntPtr(pBlob->key), encrypted, 0, 32); 
	array<BYTE>^ mac       = gcnew array<BYTE>( 4); Marshal::Copy(IntPtr(pBlob->mac), mac,       0,  4); 
	array<BYTE>^ nonce	   = gcnew array<BYTE>(cb); Marshal::Copy(IntPtr(pBlob +  1), nonce,     0, cb); 

	// закодировать параметры транспортировки
	ASN1::STB::Avest::ExchangeParameters^ transportParameters = 
		gcnew ASN1::STB::Avest::ExchangeParameters(
			gcnew ASN1::OctetString(nonce), gcnew ASN1::ObjectIdentifier(sboxOID)
	); 
	// закодировать зашифрованный ключ 
	ASN1::STB::Avest::EncryptedKey^ encodedEncryptedKey = 
		gcnew ASN1::STB::Avest::EncryptedKey(
			gcnew ASN1::OctetString(encrypted), gcnew ASN1::BitString(mac)
	); 
	// указать информацию об алгоритме
	ASN1::ISO::AlgorithmIdentifier^ algInfo = gcnew ASN1::ISO::AlgorithmIdentifier(
        gcnew ASN1::ObjectIdentifier(ASN1::STB::Avest::OID::bdh_gost_ecb), 
        transportParameters
	);
	// вернуть зашифрованный ключ
	return gcnew ASN1TransportData(algInfo, encodedEncryptedKey->Encoded); 
}

Aladdin::CAPI::IKey^ Aladdin::CAPI::STB::Avest::CSP::STB11762::ASN1KeyUnwrap::Unwrap(
	IPrivateKey^ privateKey, ASN1TransportData^ transportData)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11762::ASN1KeyUnwrap::Unwrap); 

	// получить параметры алгоритма
	STB::Avest::STB11762::IParameters^ parameters =
		(STB::Avest::STB11762::IParameters^)privateKey->KeyFactory->Parameters; 

	// извлечь параметры транспортировки
	ASN1::STB::Avest::ExchangeParameters^ transportParameters = 
		gcnew ASN1::STB::Avest::ExchangeParameters(transportData->Algorithm->Parameters); 

	// извлечь зашифрованный ключ и имитовставку
	ASN1::STB::Avest::EncryptedKey^ encodedEncryptedKey = 
		gcnew ASN1::STB::Avest::EncryptedKey(
            ASN1::Encodable::Decode(transportData->EncryptedKey)); 

	// извлечь нонку
	array<BYTE>^ nonce = transportParameters->Nonce->Value;

	// заполнить стандартный заголовок
	BLOBHEADER header = { SIMPLEBLOB,  CUR_BLOB_VERSION, 0, CALG_G28147 }; 

	// определить размер структуры для импорта
	DWORD cbBlob = sizeof(AVEST_SIMPLE_BLOB) + nonce->Length; 

	// выделить память для структуры импорта
	PAVEST_SIMPLE_BLOB pBlob = (PAVEST_SIMPLE_BLOB)_alloca(cbBlob); 

	// скопировать стандартный заголовок
	pBlob->header = header; pBlob->algID = CALG_BDH; pBlob->bitsNonce = parameters->KeyX->L;

	// записать зашифрованный ключ
	Marshal::Copy(encodedEncryptedKey->Encrypted->Value, 0, IntPtr(pBlob->key), 32); 

	// записать имитоставку ключа
	Marshal::Copy(encodedEncryptedKey->MacKey->Value, 0, IntPtr(pBlob->mac), 4);

	// записать размер нонки в битах
	pBlob->encrypt = 0x01; pBlob->bitsNonce = parameters->KeyX->L;

	// записать нонку
	Marshal::Copy(nonce, 0, IntPtr(pBlob + 1), nonce->Length); 

	// открыть контейнер для личного ключа
	CAPI::CSP::Container^ container = (CAPI::CSP::Container^)privateKey->Container; 
	
	// преобразовать тип провайдера
	CAPI::CSP::Provider^ provider = container->Store->Provider; 

	// получить описатель личного ключа
	CAPI::CSP::SessionObject<CAPI::CSP::KeyHandle> sessionPrivateKey(
		container->Handle.GetUserKey(AT_KEYEXCHANGE)
	);
	// импортировать ключ
	CAPI::CSP::KeyHandle hKey = container->ImportKey(
		sessionPrivateKey.Handle, IntPtr(pBlob), cbBlob, CRYPT_EXPORTABLE
	); 
	// вернуть импортированный ключ
	return gcnew CAPI::CSP::SessionKey(hKey); 
}
