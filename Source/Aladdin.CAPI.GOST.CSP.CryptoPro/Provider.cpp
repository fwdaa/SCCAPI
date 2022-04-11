#include "stdafx.h"
#include "Provider.h"
#include "SecretKeyType.h"
#include "GOSTR3410\GOSTR3410PrivateKey.h"
#include "Hash\GOSTR3411_1994.h"
#include "Hash\GOSTR3411_2012.h"
#include "MAC\HMAC_GOSTR3411_1994.h"
#include "MAC\HMAC_GOSTR3411_2012.h"
#include "MAC\MAC_GOST28147.h"
#include "Cipher\GOST28147.h"
#include "Wrap\RFC4357_NONE.h"
#include "Wrap\RFC4357_CPRO.h"
#include "Wrap\RFC4357_TC26.h"
#include "Sign\GOSTR3410\GOSTR3410SignHash.h"
#include "Sign\GOSTR3410\GOSTR3410VerifyHash.h"
#include "Sign\GOSTR3410\GOSTR3410SignData2001.h"
#include "Sign\GOSTR3410\GOSTR3410VerifyData2001.h"
#include "Keyx\GOSTR3410\GOSTR3410KeyAgreement.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер КриптоПро
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::BlockCipher^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::CreateGOST28147(String^ paramOID)
{$
	// получить именованные параметры алгоритма
	ASN1::GOST::GOST28147ParamSet^ namedParameters = 
		ASN1::GOST::GOST28147ParamSet::Parameters(paramOID);

	// создать алгоритм шифрования 
	return gcnew Cipher::GOST28147(
		this, Handle, paramOID, namedParameters->KeyMeshing->Algorithm->Value
	); 
}

array<Aladdin::CAPI::SecurityInfo^>^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::EnumerateAllObjects(Scope scope)
{$
	// создать список считывателей
	List<String^>^ names = gcnew List<String^>(); 

    // получить подсистему смарт-карт
    PCSC::Provider^ cardProvider = PCSC::Windows::Provider::Instance; 

	// перечислить считыватели
	array<PCSC::Reader^>^ readers = cardProvider->EnumerateReaders(PCSC::ReaderScope::System); 

	// для каждой смарт-карты
	for (int i = 0; i < readers->Length; i++) 
	try {
		// при наличии смарт-карты добавить имя считывателя
		if (readers[i]->GetState() == PCSC::ReaderState::Card) names->Add(readers[i]->Name); 
	}
    // создать список описаний объектов
	catch (Exception^) {} List<SecurityInfo^>^ infos = gcnew List<SecurityInfo^>(); 

    // при перечислении системных объектов
    if (scope == Scope::Any || scope == Scope::System)
    {
		// перечислить все контейнеры
		array<String^>^ fullNames = Handle->EnumerateContainers(CRYPT_FQCN | CRYPT_MACHINE_KEYSET); 

		// для всех считывателей
		for (int i = 0; i < names->Count; i++)
		{
			// для всех контейнеров
			for each (String^ fullName in fullNames)
			{
				// проверить имя считывателя
				if (!fullName->StartsWith(String::Format("\\\\.\\{0}\\", names[i]))) continue; 

				// указать имя хранилища
				String^ storeName = String::Format("Card\\{0}", names[i]); 

				// извлечь имя контейнера
				String^ name = fullName->Substring(4 + names[i]->Length + 1); 

				// добавить информацию о контейнере
				infos->Add(gcnew SecurityInfo(Scope::System, storeName, name)); 
			}
		}
		// для всех контейнеров
		for each (String^ fullName in fullNames)
		{
			// проверить принадлежность реестру
			if (!fullName->StartsWith("\\\\.\\REGISTRY\\")) continue; 
			
			// извлечь имя контейнера
			String^ name = fullName->Substring(13); 

			// добавить информацию о контейнере
			infos->Add(gcnew SecurityInfo(Scope::System, "HKLM", name)); 
		}
	}
    // при перечислении пользовательских объектов
    if (scope == Scope::Any || scope == Scope::User)
    {
		// перечислить все контейнеры
		array<String^>^ fullNames = Handle->EnumerateContainers(CRYPT_FQCN); 

		// для всех контейнеров
		for each (String^ fullName in fullNames)
		{
			// проверить принадлежность реестру
			if (!fullName->StartsWith("\\\\.\\REGISTRY\\")) continue; 

			// извлечь имя контейнера
			String^ name = fullName->Substring(13); 

			// добавить информацию о контейнере
			infos->Add(gcnew SecurityInfo(Scope::User, "HKCU", name)); 
        }
	}
    // вернуть список описаний объектов
    return infos->ToArray(); 
}

Aladdin::CAPI::CSP::SecretKeyType^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// получить тип ключа
	if (keySize == 32) return gcnew SecretKeyType(CALG_G28147       ); 
	if (keySize == 64) return gcnew SecretKeyType(CALG_SYMMETRIC_512); 

	// неподдерживаемый алгоритм
	throw gcnew NotSupportedException(); 
}

String^ Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ConvertKeyOID(ALG_ID keyOID) 
{$
    if (keyOID == CALG_GR3410EL   ) return ASN1::GOST::OID::gostR3410_2001; 
    if (keyOID == CALG_DH_EL_SF   ) return ASN1::GOST::OID::gostR3410_2001;
    if (keyOID == CALG_DH_EL_EPHEM) return ASN1::GOST::OID::gostR3410_2001;

    if (version >= 0x0400)
    {
        if (keyOID == CALG_GR3410_12_256         ) return ASN1::GOST::OID::gostR3410_2012_256; 
        if (keyOID == CALG_DH_GR3410_12_256_SF   ) return ASN1::GOST::OID::gostR3410_2012_256;
        if (keyOID == CALG_DH_GR3410_12_256_EPHEM) return ASN1::GOST::OID::gostR3410_2012_256;
        if (keyOID == CALG_GR3410_12_512         ) return ASN1::GOST::OID::gostR3410_2012_512; 
        if (keyOID == CALG_DH_GR3410_12_512_SF   ) return ASN1::GOST::OID::gostR3410_2012_512;
        if (keyOID == CALG_DH_GR3410_12_512_EPHEM) return ASN1::GOST::OID::gostR3410_2012_512;
    }
	// неподдерживаемый ключ
	throw gcnew NotSupportedException(); 
}

ALG_ID Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ConvertKeyOID(String^ keyOID, DWORD keyType)
{$
    if (keyOID == ASN1::GOST::OID::gostR3410_2001)
    {
        return (keyType == AT_KEYEXCHANGE) ? CALG_DH_EL_SF : CALG_GR3410EL; 
    }
    if (version >= 0x0400)
    {
        if (keyOID == ASN1::GOST::OID::gostR3410_2012_256)
        {
            return (keyType == AT_KEYEXCHANGE) ? CALG_DH_GR3410_12_256_SF : CALG_GR3410_12_256; 
        }
        if (keyOID == ASN1::GOST::OID::gostR3410_2012_512)
        {
            return (keyType == AT_KEYEXCHANGE) ? CALG_DH_GR3410_12_512_SF : CALG_GR3410_12_512; 
        }
    }
	// неподдерживаемый ключ
	throw gcnew NotSupportedException(); 
}

String^ Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::GetExportKeyOID(String^ keyOID, DWORD keyType)
{
    if (keyOID == ASN1::GOST::OID::gostR3410_2001)
    {
        return (keyType == AT_KEYEXCHANGE) ? ASN1::GOST::OID::gostR3410_2001_SSDH : keyOID; 
	}
    if (version >= 0x0400)
    {
        if (keyOID == ASN1::GOST::OID::gostR3410_2012_256)
        {
			/* TODO */
            return (keyType == AT_KEYEXCHANGE) ? ASN1::GOST::OID::gostR3410_2012_DH_256 : keyOID; 
        }
        if (keyOID == ASN1::GOST::OID::gostR3410_2012_512)
        {
			/* TODO */
            return (keyType == AT_KEYEXCHANGE) ? ASN1::GOST::OID::gostR3410_2012_DH_512 : keyOID; 
        }
    }
	// неподдерживаемый ключ
	throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::KeyWrap^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::CreateExportKeyWrap(
    CAPI::CSP::ContextHandle^ hContext, ALG_ID exportID, String^ sboxOID, array<BYTE>^ ukm)
{$
    if (exportID == CALG_PRO_EXPORT)
    {
        // создать алгоритм шифрования ключа
		return gcnew Wrap::RFC4357_CPRO(this, hContext, sboxOID, ukm);
    }
    if (exportID == CALG_PRO12_EXPORT)
    {
        // создать алгоритм шифрования ключа
        return gcnew Wrap::RFC4357_TC26(this, hContext, sboxOID, ukm);
    } 
	// неподдерживаемый алгоритм
	throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ImportKeyPair(
	CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	// получить параметры алгоритма
	CAPI::GOST::GOSTR3410::IECParameters^ gostParameters = 
		(CAPI::GOST::GOSTR3410::IECParameters^) publicKey->Parameters;

	// преобразовать тип ключа
	CAPI::GOST::GOSTR3410::IECPrivateKey^ gostPrivateKey = 
		(CAPI::GOST::GOSTR3410::IECPrivateKey^) privateKey; 

	// определить идентификатор ключа в структуре
	String^ keyOID = GetExportKeyOID(publicKey->KeyOID, keyType); 

	// указать атрибуты ключа
	ASN1::GOST::CryptoProPrivateKeyAttributes attributes = 
		ASN1::GOST::CryptoProPrivateKeyAttributes::Exportable;

	// указать атрибуты ключа
	if (keyType == AT_KEYEXCHANGE) 
	{ 
		// скорректрировать атрибуты ключа
		attributes = attributes | ASN1::GOST::CryptoProPrivateKeyAttributes::Exchange;
	}
	// закодировать открытый ключ
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = publicKey->Encoded; 

	// создать структуру параметров открытого ключа
	ASN1::ISO::AlgorithmIdentifier^ algorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
			gcnew ASN1::ObjectIdentifier(keyOID), 
			publicKeyInfo->Algorithm->Parameters
	); 
	// создать структуру параметров личного ключа
	ASN1::GOST::CryptoProPrivateKeyParameters^ parameters =
		gcnew ASN1::GOST::CryptoProPrivateKeyParameters(
			gcnew ASN1::BitFlags(attributes), algorithm
	);
	// сгенерировать ключ шифрования ключа
	Using<CAPI::CSP::KeyHandle^> hKEK(
		Handle->GenerateKey(CALG_G28147, CRYPT_EXPORTABLE)
	); 
	// создать объект ключа
	CAPI::CSP::SecretKey KEK(this, Keys::GOST::Instance, hKEK.Get()); 

	// получить идентификатор таблицы подстановок
	String^ sboxOID = hKEK.Get()->GetString(KP_CIPHEROID, 0);

	// создать нулевой UKM
	array<BYTE>^ ukm = gcnew array<BYTE>(SEANCE_VECTOR_LEN);   

	// создать алгоритм шифрования ключа
	Using<KeyWrap^> keyWrap(CreateExportKeyWrap(
		Handle, GetExportID(publicKey->KeyOID), sboxOID, ukm
	)); 
	// получить значение личного ключа
	array<BYTE>^ valueCEK = Math::Convert::FromBigInteger(
		gostPrivateKey->D, Endian, (gostParameters->Order->BitLength + 7) / 8
	); 
	// указать тип ключа
	SecretKeyFactory^ typeCEK = (valueCEK->Length == 32) ? 
		Keys::GOST::Instance : SecretKeyFactory::Generic; 

	// указать объект ключа
	Using<ISecretKey^> CEK(typeCEK->Create(valueCEK)); 

	// зашифровать значение личного ключа
	array<BYTE>^ wrapped = keyWrap.Get()->Wrap(nullptr, %KEK, CEK.Get()); 

	// выделить буфер для зашифрованного ключа
	array<BYTE>^ encKey = gcnew array<BYTE>(wrapped->Length - EXPORT_IMIT_SIZE); 

	// извлечь значение зашифрованного ключа
	Array::Copy(wrapped, 0, encKey, 0, encKey->Length); 

	// выделить буфер для имитовставки
	array<BYTE>^ macKey = gcnew array<BYTE>(EXPORT_IMIT_SIZE); 

	// извлечь значение имитовставки
	Array::Copy(wrapped, encKey->Length, macKey, 0, EXPORT_IMIT_SIZE); 
		
	// создать структуру зашифрованного ключа
	ASN1::GOST::EncryptedKey^ encryptedKey = gcnew ASN1::GOST::EncryptedKey(
		gcnew ASN1::OctetString(encKey), nullptr, gcnew ASN1::OctetString(macKey)
	); 
	// создать структуру экспорта
	ASN1::GOST::CryptoProKeyTransferContent^ keyTransferContent = 
		gcnew ASN1::GOST::CryptoProKeyTransferContent(
			gcnew ASN1::OctetString(ukm), encryptedKey, parameters
	); 
	// создать алгоритм диверсификации ключа
	Using<KeyDerive^> keyDerive(((Wrap::RFC4357^)keyWrap.Get())->GetKDFAlgorithm(Handle)); 

	// создать алгоритм вычисления имитовставки
	Using<Mac^> macAlgorithm(gcnew MAC::GOST28147(
		this, Handle, sboxOID, ASN1::GOST::OID::keyMeshing_none, ukm
	)); 
	// создать диверсифицированный ключ
	Using<ISecretKey^> sessionKey(keyDerive.Get()->DeriveKey(
		%KEK, ukm, macAlgorithm.Get()->KeyFactory, 32
	)); 
	// вычислить имитовставку от структуры
	array<BYTE>^ mac = macAlgorithm.Get()->MacData(sessionKey.Get(), 
		keyTransferContent->Encoded, 0, keyTransferContent->Encoded->Length
	); 
	// создать структуру с имитовставкой
	ASN1::GOST::CryptoProKeyTransfer^ keyTransfer = 
		gcnew ASN1::GOST::CryptoProKeyTransfer(
			keyTransferContent, gcnew ASN1::OctetString(mac)
	); 
	// задать фиксированный заголовок
	BLOBHEADER blobHeader = { PRIVATEKEYBLOB, BLOB_VERSION, 0, 
		ConvertKeyOID(publicKey->KeyOID, keyType) 
	}; 
	// задать заголовок ключа 
	CRYPT_PUBKEYPARAM keyHeader = { GR3410_2_MAGIC, (UINT)encKey->Length }; 

	// определить требуемый размер буфера
	DWORD cbBlob = sizeof(CRYPT_PUBKEY_INFO_HEADER) + keyTransfer->Encoded->Length; 

	// выделить буфер требуемогго размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	CRYPT_PUBKEY_INFO_HEADER* pBlob = (CRYPT_PUBKEY_INFO_HEADER*)(PBYTE)ptrBlob; 

	// задать заголовок
	pBlob->BlobHeader = blobHeader; pBlob->KeyParam = keyHeader; 

	// определить смещение структуры
	DWORD offset = sizeof(CRYPT_PUBKEY_INFO_HEADER); 

	// скопировать структуру с имитовставкой
	Array::Copy(keyTransfer->Encoded, 0, blob, offset, keyTransfer->Encoded->Length); 

	// указать идентификатор алгоритма
	hKEK.Get()->SetLong(KP_ALGID, GetExportID(publicKey->KeyOID), 0); 

	// импортировать пару ключей
	return ImportKey(container, hKEK.Get(), IntPtr(pBlob), cbBlob, keyFlags); 
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ImportPublicKey(
	CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType)
{$
    // получить идентификатор ключа
	ALG_ID algID = ConvertKeyOID(publicKey->KeyOID, AT_KEYEXCHANGE); 

	// закодировать открытый ключ
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ info = publicKey->Encoded; 

    // извлечь закодированные параметры
    array<BYTE>^ encodedParams = info->Algorithm->Parameters->Encoded; 

    // преобразовать тип ключа
    GOST::GOSTR3410::IECPublicKey^ ecPublicKey = (GOST::GOSTR3410::IECPublicKey^)publicKey; 

    // преобразовать тип параметров
	GOST::GOSTR3410::IECParameters^ ecParameters = (GOST::GOSTR3410::IECParameters^)publicKey->Parameters; 
        
    // создать буфер для объединения точек
    array<BYTE>^ xy = gcnew array<BYTE>((ecParameters->Order->BitLength + 7) / 8 * 2); 

    // закодировать координаты точки
    Math::Convert::FromBigInteger(ecPublicKey->Q->X, Endian, xy,              0, xy->Length / 2);
    Math::Convert::FromBigInteger(ecPublicKey->Q->Y, Endian, xy, xy->Length / 2, xy->Length / 2);

    // определить размер структуры для импорта
    DWORD cbBlob = sizeof(CRYPT_PUBKEY_INFO_HEADER) + encodedParams->Length + xy->Length; 

    // выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
    CRYPT_PUBKEY_INFO_HEADER* pHeader = (CRYPT_PUBKEY_INFO_HEADER*)(PBYTE)ptrBlob; 

    // обнулить выделенный буфер
    std::memset(pHeader, 0, cbBlob); pHeader->BlobHeader.aiKeyAlg = algID; 

    // задать фиксированный заголовок
    pHeader->BlobHeader.bType = PUBLICKEYBLOB; pHeader->BlobHeader.bVersion = BLOB_VERSION; 

	// задать заголовок ключа 
    pHeader->KeyParam.Magic = GR3410_2_MAGIC; pHeader->KeyParam.BitLen = xy->Length * 8; 

	// скопировать параметры
	Array::Copy(encodedParams, 0, blob, sizeof(CRYPT_PUBKEY_INFO_HEADER), encodedParams->Length); 

	// скопировать значение ключа в буфер
	Array::Copy(xy, 0, blob, sizeof(CRYPT_PUBKEY_INFO_HEADER) + encodedParams->Length, xy->Length);  

	// импортировать открытый ключ
	return hContext->ImportKey(nullptr, IntPtr(pHeader), cbBlob, 0); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ExportPublicKey(
	CAPI::CSP::KeyHandle^ hPublicKey)
{$
	// определить размер буфера
	DWORD cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0);

	// выделить память для структуры экспорта
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	CRYPT_PUBKEY_INFO_HEADER* pBlob = (CRYPT_PUBKEY_INFO_HEADER*)(PBYTE)ptrBlob;  

	// экспортировать открытый ключ
	cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr(pBlob), cbBlob);

    // определить идентификатор ключа
    String^ keyOID = ConvertKeyOID(pBlob->BlobHeader.aiKeyAlg); 

    // определить размер открытого ключа в байтах
    DWORD publicSize = (pBlob->KeyParam.BitLen + 7) / 8; 

	// раскодировать параметры
	ASN1::IEncodable^ encodedParams = ASN1::Encodable::Decode(
		blob,    sizeof(CRYPT_PUBKEY_INFO_HEADER), 
		cbBlob - sizeof(CRYPT_PUBKEY_INFO_HEADER)
	); 
	// закодировать параметры с идентификатором
	ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
            gcnew ASN1::ObjectIdentifier(keyOID), encodedParams
    );  
	// выделить память для открытого ключа
	array<BYTE>^ xy = gcnew array<BYTE>(publicSize); 

	// определить смещение открытого ключа
	DWORD offsetKey = sizeof(CRYPT_PUBKEY_INFO_HEADER) + encodedParams->Encoded->Length; 

	// извлечь значение открытого ключа
    Array::Copy(blob, offsetKey, xy, 0, publicSize); 

	// закодировать значение открытого ключа 
	array<BYTE>^ encoded = ASN1::OctetString(xy).Encoded; 

	// закодировать ключ
	ASN1::BitString^ encodedKey = gcnew ASN1::BitString(encoded, encoded->Length * 8); 

	// вернуть закодированный ключ с параметрами
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
}

Aladdin::CAPI::CSP::PrivateKey^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType)
{$
	// проверить тип параметров
	if (dynamic_cast<GOST::GOSTR3410::IECPublicKey^>(publicKey) != nullptr)
	{
		// преобразовать тип параметров
		GOST::GOSTR3410::IECPublicKey^ ecPublicKey = (GOST::GOSTR3410::IECPublicKey^)publicKey; 

		// указать идентификатор ключа
		array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

		// создать личный ключ
		return gcnew GOSTR3410::PrivateKey(this, scope, ecPublicKey, hKeyPair, keyID, keyType);
	}
	// вызвать базовую функцию
	else return CAPI::CSP::Provider::GetPrivateKey(scope, publicKey, hKeyPair, keyType);
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::CreateAlgorithm(
	CAPI::Factory^ factory, SecurityStore^ scope, 
	String^ oid, ASN1::IEncodable^ parameters, System::Type^ type) 
{$
	for (int i = 0; i < 1; i++)
	{
		// для алгоритмов хэширования
		if (type == CAPI::Hash::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3411_94) 
			{
				// для закодированного идентификатора
				if (parameters->Tag == ASN1::Tag::ObjectIdentifier) 					
				{
					// раскодировать идентификатор параметров
					oid = ASN1::ObjectIdentifier(parameters).Value;
				}
				// установить идентификатор по умолчанию
				else oid = ASN1::GOST::OID::hashes_cryptopro; 
 
				// создать алгоритм хэширования
				return gcnew Hash::GOSTR3411_1994(this, Handle, oid);
			}
			if (oid == ASN1::GOST::OID::gostR3411_2012_256) 
			{
				// создать алгоритм хэширования
				return gcnew Hash::GOSTR3411_2012(this, Handle, 256);
			}
			if (oid == ASN1::GOST::OID::gostR3411_2012_512) 
			{
				// создать алгоритм хэширования
				return gcnew Hash::GOSTR3411_2012(this, Handle, 512);
			}
		}
		// для алгоритмов вычисления имитовставки
		else if (type == Mac::typeid)
		{
			if (oid == ASN1::GOST::OID::gost28147_89_MAC) 
			{
				// раскодировать параметры алгоритма
				ASN1::GOST::GOST28147CipherParameters^ algParameters = 
					gcnew ASN1::GOST::GOST28147CipherParameters(parameters); 

				// определить идентификатор таблицы подстановок
				String^ sboxOID = algParameters->ParamSet->Value; 

				// получить именованные параметры алгоритма
				ASN1::GOST::GOST28147ParamSet^ namedParameters = 
					ASN1::GOST::GOST28147ParamSet::Parameters(sboxOID);
 
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::GOST28147(this, Handle, sboxOID, 
					namedParameters->KeyMeshing->Algorithm->Value, algParameters->IV->Value
				);
			}
			if (oid == ASN1::GOST::OID::gostR3411_94_HMAC) 
			{
				// для закодированного идентификатора
				if (parameters->Tag == ASN1::Tag::ObjectIdentifier) 					
				{
					// раскодировать идентификатор параметров
					oid = ASN1::ObjectIdentifier(parameters).Value;
				}
				// установить идентификатор по умолчанию
				else oid = ASN1::GOST::OID::hashes_cryptopro; 
 
				// создать алгоритм хэширования
				return gcnew MAC::HMAC_GOSTR3411_1994(this, Handle, oid);
			}
			if (oid == ASN1::GOST::OID::gostR3411_2012_HMAC_256) 
			{
				// создать алгоритм хэширования
				return gcnew MAC::HMAC_GOSTR3411_2012(this, Handle, 256);
			}
			if (oid == ASN1::GOST::OID::gostR3411_2012_HMAC_512) 
			{
				// создать алгоритм хэширования
				return gcnew MAC::HMAC_GOSTR3411_2012(this, Handle, 512);
			}
		}
		// для алгоритмов симметричного шифрования
		else if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::GOST::OID::gost28147_89)
			{ 
				// установить значения по умолчанию
				CipherMode^ mode = gcnew CipherMode::ECB();	PaddingMode padding = PaddingMode::None;

				// раскодировать параметры алгоритма
				ASN1::GOST::GOST28147CipherParameters^ algParameters = 
					gcnew ASN1::GOST::GOST28147CipherParameters(parameters); 

				// определить идентификатор параметров
				ASN1::ObjectIdentifier^ paramSet = algParameters->ParamSet; 

				// создать алгоритм шифрования
				Using<IBlockCipher^> blockCipher(CreateBlockCipher(scope, "GOST28147", paramSet)); 

				// извлечь синхропосылку
				array<BYTE>^ iv = algParameters->IV->Value; 
		 
				// получить именованные параметры алгоритма
				ASN1::GOST::GOST28147ParamSet^ namedParameters = 
					ASN1::GOST::GOST28147ParamSet::Parameters(paramSet->Value);

				// в зависимости от режима 
				switch (namedParameters->Mode->Value->IntValue)
				{
				// определить режим алгоритма
				case 0: mode = gcnew CAPI::CipherMode::CTR(iv, 8); padding = PaddingMode::None;  break;  
				case 1: mode = gcnew CAPI::CipherMode::CFB(iv, 8); padding = PaddingMode::None;  break;
				case 2: mode = gcnew CAPI::CipherMode::CBC(iv, 8); padding = PaddingMode::PKCS5; break;
				}
				// вернуть режим шифрования
				return gcnew Cipher::GOST28147::BlockMode((CAPI::CSP::BlockCipher^)blockCipher.Get(), mode, padding);
			}
		}
		// для алгоритмов наследования ключа
		else if (type == KeyDerive::typeid)
		{
			if (oid == ASN1::GOST::OID::keyMeshing_cryptopro) 
			{
				// раскодировать параметры алгоритма
				ASN1::ObjectIdentifier^ paramSet = gcnew ASN1::ObjectIdentifier(parameters); 

				// создать алгоритм шифрования
				Using<CAPI::CSP::BlockCipher^> blockCipher(gcnew Cipher::GOST28147(
					this, Handle, paramSet->Value, ASN1::GOST::OID::keyMeshing_none
				)); 
				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::ECB(); 
                
				// создать алгоритм шифрования блока
				Using<CAPI::Cipher^> cipher(blockCipher.Get()->CreateBlockMode(mode)); 

				// создать алгоритм наследования ключа
				return gcnew GOST::Derive::KeyMeshing(cipher.Get()); 
			}
		}
		// для алгоритмов шифрования ключа
		else if (type == KeyWrap::typeid)
		{
			if (oid == ASN1::GOST::OID::keyWrap_none) 
			{
				// раскодировать параметры алгоритма
				ASN1::GOST::KeyWrapParameters^ algParameters = 
					gcnew ASN1::GOST::KeyWrapParameters(parameters); 

				// определить идентификатор таблицы подстановок
				String^ sboxOID = algParameters->ParamSet->Value; 

				// определить UKM
				array<BYTE>^ ukm = (algParameters->Ukm != nullptr) ? algParameters->Ukm->Value : nullptr; 

				// создать алгоритм шифрования ключа
				return gcnew Wrap::RFC4357_NONE(this, Handle, sboxOID, ukm);
			}
			if (oid == ASN1::GOST::OID::keyWrap_cryptopro) 
			{
				// раскодировать параметры алгоритма
				ASN1::GOST::KeyWrapParameters^ algParameters = 
					gcnew ASN1::GOST::KeyWrapParameters(parameters); 

				// определить идентификатор таблицы подстановок
				String^ sboxOID = algParameters->ParamSet->Value; 

				// определить UKM
				array<BYTE>^ ukm = (algParameters->Ukm != nullptr) ? algParameters->Ukm->Value : nullptr; 

				// создать алгоритм шифрования ключа
				return gcnew Wrap::RFC4357_CPRO(this, Handle, sboxOID, ukm);
			}
		}
		// для алгоритмов подписи хэш-значения
		else if (type == SignHash::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3410_2001) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::GOSTR3410::SignHash(this, CALG_GR3411);
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_256) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::GOSTR3410::SignHash(this, CALG_GR3411_2012_256);
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_512) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::GOSTR3410::SignHash(this, CALG_GR3411_2012_512);
			}
		}
		// для алгоритмов подписи хэш-значения
		else if (type == VerifyHash::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3410_2001) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::GOSTR3410::VerifyHash(this, CALG_GR3411);
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_256) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::GOSTR3410::VerifyHash(this, CALG_GR3411_2012_256);
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_512) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::GOSTR3410::VerifyHash(this, CALG_GR3411_2012_512);
			}
		}
		// для алгоритмов подписи данных
		else if (type == SignData::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3411_94_R3410_2001) 
			{
				// создать алгоритм подписи хэш-значения
				Using<SignHash^> signHash(gcnew Sign::GOSTR3410::SignHash(this, CALG_GR3411));

				// вернуть алгоритм подписи данных
				return gcnew Sign::GOSTR3410::SignData2001(this, signHash.Get()); 
			}
		}
		// для алгоритмов подписи данных
		else if (type == VerifyData::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3411_94_R3410_2001) 
			{
				// создать алгоритм подписи хэш-значения
				Using<VerifyHash^> verifyHash(gcnew Sign::GOSTR3410::VerifyHash(this, CALG_GR3411));

				// вернуть алгоритм подписи данных
				return gcnew Sign::GOSTR3410::VerifyData2001(this, verifyHash.Get()); 
			}
		}
		// для алгоритмов согласования общего ключа
		else if (type == IKeyAgreement::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3410_2001)
			{
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::GOSTR3410::KeyAgreement(this, 8); 
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_256)
			{
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::GOSTR3410::KeyAgreement(this, 8); 
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_512)
			{
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::GOSTR3410::KeyAgreement(this, 8); 
			}
		}
	}
    // вызвать базовую функцию
	return CAPI::GOST::Factory::RedirectAlgorithm(factory, scope, oid, parameters, type);
}

