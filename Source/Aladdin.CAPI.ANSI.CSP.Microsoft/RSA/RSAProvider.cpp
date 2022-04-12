#include "..\stdafx.h"
#include "RSAProvider.h"
#include "..\SecretKeyType.h"
#include "..\RSA\RSAPrivateKey.h"
#include "..\RSA\RSAKeyPairGenerator.h"
#include "..\MAC\\HMAC.h"
#include "..\Sign\RSA\RSASignHash.h"
#include "..\Sign\RSA\RSAVerifyHash.h"
#include "..\Keyx\RSA\RSAEncipherment.h"
#include "..\Keyx\RSA\RSADecipherment.h"
#include "..\Keyx\RSA\RSATransportKeyWrap.h"
#include "..\Keyx\RSA\RSATransportKeyUnwrap.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер RSA
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKeyType^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// в зависимости от типа алгоритма
	if (dynamic_cast<Keys::DES^>(keyFactory) != nullptr) 
	{
		// указать идентификатор алгоритма
		return gcnew SecretKeyType(CALG_DES); 
	}
	// в зависимости от типа алгоритма
	if (dynamic_cast<Keys::RC4^>(keyFactory) != nullptr) 
	{
		// указать идентификатор алгоритма
		return gcnew SecretKeyType(CALG_RC4);
	}
	// в зависимости от типа алгоритма
	if (dynamic_cast<Keys::RC2^>(keyFactory) != nullptr) 
	{
		// указать идентификатор алгоритма
		return gcnew SecretKeyType(CALG_RC2);
	}
	// указать идентификатор алгоритма по умолчанию
	return gcnew SecretKeyType(CALG_RC2); 
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::ImportKeyPair(
	CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	ALG_ID algID = keyType; 

	// определить идентификатор алгоритма
	if (keyType == AT_KEYEXCHANGE) algID = CALG_RSA_KEYX; else 
	if (keyType == AT_SIGNATURE  ) algID = CALG_RSA_SIGN; 

	// преобразовать тип ключей
	ANSI::RSA::IPublicKey^  rsaPublicKey  = (ANSI::RSA::IPublicKey ^)publicKey; 
	ANSI::RSA::IPrivateKey^ rsaPrivateKey = (ANSI::RSA::IPrivateKey^)privateKey; 

	// извлечь значение экспоненты и модуля
	Math::BigInteger^ exponent = rsaPublicKey->PublicExponent; 
	Math::BigInteger^ modvalue = rsaPublicKey->Modulus; 

	// проверить размер экспоненты
	if (exponent > Math::BigInteger::ValueOf(UInt32::MaxValue)) throw gcnew InvalidDataException();

	// закодировать значение модуля
	array<BYTE>^ modulus = Math::Convert::FromBigInteger(modvalue, Endian); 

	// указать фиксированный заголовок
	PUBLICKEYSTRUC header = { PRIVATEKEYBLOB, CUR_BLOB_VERSION, 0, algID }; 

	// указать заголовок RSA
	RSAPUBKEY headerRSA = { 0x32415352, (UINT)modvalue->BitLength, (DWORD)exponent->LongValue }; 

	// извлечь модуль и параметры личного ключа
	array<BYTE>^ prime1       = Math::Convert::FromBigInteger(rsaPrivateKey->PrimeP         , Endian);
	array<BYTE>^ prime2       = Math::Convert::FromBigInteger(rsaPrivateKey->PrimeQ         , Endian); 
	array<BYTE>^ exponent1    = Math::Convert::FromBigInteger(rsaPrivateKey->PrimeExponentP , Endian);
	array<BYTE>^ exponent2    = Math::Convert::FromBigInteger(rsaPrivateKey->PrimeExponentQ , Endian);
	array<BYTE>^ coefficient  = Math::Convert::FromBigInteger(rsaPrivateKey->CrtCoefficient , Endian);
	array<BYTE>^ privExponent = Math::Convert::FromBigInteger(rsaPrivateKey->PrivateExponent, Endian);

	// определить смещение модуля в структуре
	DWORD ofs = sizeof(header) + sizeof(headerRSA); DWORD cb = headerRSA.bitlen / 16; 

	// выделить память для структуры импорта
	array<BYTE>^ blob = gcnew array<BYTE>(ofs + 9 * cb); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 

	// скопировать фиксированный заголовок и заголовок RSA
	*pBlob = header; *(RSAPUBKEY*)(pBlob + 1) = headerRSA; 

	// скопировать значение модуля и закрытую часть
	Array::Copy(modulus     , 0, blob, ofs + 0 * cb, modulus     ->Length);
	Array::Copy(prime1      , 0, blob, ofs + 2 * cb, prime1      ->Length); 
	Array::Copy(prime2      , 0, blob, ofs + 3 * cb, prime2      ->Length); 
	Array::Copy(exponent1   , 0, blob, ofs + 4 * cb, exponent1   ->Length); 
	Array::Copy(exponent2   , 0, blob, ofs + 5 * cb, exponent2   ->Length); 
	Array::Copy(coefficient , 0, blob, ofs + 6 * cb, coefficient ->Length); 
	Array::Copy(privExponent, 0, blob, ofs + 7 * cb, privExponent->Length); 

	// импортировать пару ключей
	return ImportKey(container, nullptr, IntPtr(ptrBlob), blob->Length, keyFlags); 
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::ImportPublicKey(
	CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType)
{$
	// преобразовать идентификатор ключа
	ALG_ID algID = ConvertKeyOID(publicKey->KeyOID, keyType); 

	// преобразовать тип ключа
	ANSI::RSA::IPublicKey^ rsaPublicKey = (ANSI::RSA::IPublicKey^)publicKey; 

	// извлечь значение экспоненты и модуля
	Math::BigInteger^ exponent = rsaPublicKey->PublicExponent; 
	Math::BigInteger^ modvalue = rsaPublicKey->Modulus; 

	// проверить размер экспоненты
	if (exponent > Math::BigInteger::ValueOf(UInt32::MaxValue)) throw gcnew InvalidDataException();

	// закодировать значение модуля
	array<BYTE>^ modulus = Math::Convert::FromBigInteger(modvalue, Endian); 

	// указать фиксированный заголовок
	PUBLICKEYSTRUC header = { PUBLICKEYBLOB, CUR_BLOB_VERSION, 0, algID }; 

	// указать заголовок RSA
	RSAPUBKEY headerRSA = { 0x31415352, (UINT)modvalue->BitLength, (DWORD)exponent->LongValue }; 

	// определить смещение модуля в структуре
	DWORD ofs = sizeof(header) + sizeof(headerRSA); DWORD cb = headerRSA.bitlen / 16; 

	// выделить память для структуры импорта
	array<BYTE>^ blob = gcnew array<BYTE>(ofs + 2 * cb); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 

	// скопировать фиксированный заголовок и заголовок RSA
	*pBlob = header; *(RSAPUBKEY*)(pBlob + 1) = headerRSA; 

	// скопировать значение модуля
	Array::Copy(modulus, 0, blob, ofs, modulus->Length);

	// импортировать пару ключей
	return hContext->ImportKey(nullptr, IntPtr(ptrBlob), blob->Length, 0); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::ExportPublicKey(
	CAPI::CSP::KeyHandle^ hPublicKey)
{$
	// указать идентификатор ключа
	String^ keyOID = ConvertKeyOID(hPublicKey->GetLong(KP_ALGID, 0)); 

	// определить размер буфера
	DWORD cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0);

	// выделить память для структуры экспорта
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; RSAPUBKEY* pInfo = (RSAPUBKEY*)(pBlob + 1); 

	// экспортировать открытый ключ
	cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr(pBlob), cbBlob);

	// выделить память для модуля
	array<BYTE>^ buffer = gcnew array<BYTE>(pInfo->bitlen / 8);

	// скопировать значение модуля
	Array::Copy(blob, sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY), buffer, 0, buffer->Length); 

	// раскодировать значение модуля
	Math::BigInteger^ modulus = Math::Convert::ToBigInteger(buffer, Endian);  

	// закодировать открытый ключ
	ASN1::ISO::PKCS::PKCS1::RSAPublicKey^ encoded = 
		gcnew ASN1::ISO::PKCS::PKCS1::RSAPublicKey(
			gcnew ASN1::Integer(modulus), gcnew ASN1::Integer(pInfo->pubexp)
	); 
	// закодировать параметры алгоритма
	ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
            gcnew ASN1::ObjectIdentifier(keyOID), 
            ASN1::Null::Instance
    ); 
	// получить закодированное представление ключа
	ASN1::BitString^ encodedKey = gcnew ASN1::BitString(encoded->Encoded); 

	// вернуть закодированный ключ и параметры
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
}
		
Aladdin::CAPI::CSP::PrivateKey^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType)
{$
	// проверить идентификатор параметров
	if (dynamic_cast<ANSI::RSA::IPublicKey^>(publicKey) != nullptr)
    {
		// преобразовать тип параметров
		ANSI::RSA::IPublicKey^ rsaPublicKey = (ANSI::RSA::IPublicKey^)publicKey;

		// указать идентификатор ключа
		array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

		// создать личный ключ
		return gcnew RSA::PrivateKey(this, scope, rsaPublicKey, hKeyPair, keyID, keyType); 
    }
	// вызвать базовую функцию
	return CAPI::CSP::Provider::GetPrivateKey(scope, publicKey, hKeyPair, keyType); 
}

Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::CreateGenerator(
	Factory^ factory, SecurityObject^ scope, 
	IRand^ rand, String^ keyOID, IParameters^ parameters)
{$
	// указать идентификатор алгоритма
	keyOID = CAPI::ANSI::Factory::RedirectKeyName(keyOID); 

	// проверить идентификатор параметров
	if (keyOID == ASN1::ISO::PKCS::PKCS1::OID::rsa)
	{
		// преобразовать тип параметров
		ANSI::RSA::IParameters^ rsaParameters = ANSI::RSA::Parameters::Convert(parameters);

		// проверить значение экспоненты
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr; 
		
		// создать алгоритм генерации ключей
		return gcnew RSA::KeyPairGenerator(this, scope, rand, rsaParameters);
	}
	return nullptr; 
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, String^ oid, 
	ASN1::IEncodable^ parameters, System::Type^ type)
{$
	for (int i = 0; i < 1; i++)
	{
		if (type == Mac::typeid)
		{
			if (oid == ASN1::ANSI::OID::ipsec_hmac_md5)
			{
				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::rsa_md5), 
						ASN1::Null::Instance
				); 
				// создать алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// проверить тип алгоритма
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break; 
				
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha1)
			{
				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1),
						ASN1::Null::Instance
				); 
				// создать алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// проверить тип алгоритма
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break; 
				
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha2_256)
			{
				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_256), 
						ASN1::Null::Instance
				); 
				// создать алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// проверить тип алгоритма
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break; 
				
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha2_384)
			{
				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_384), 
						ASN1::Null::Instance
				); 
				// создать алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// проверить тип алгоритма
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break; 
				
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha2_512)
			{
				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_512), 
						ASN1::Null::Instance
				); 
				// создать алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// проверить тип алгоритма
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break;
				
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
		}
		// для алгоритмов асимметричного шифрования
		else if (type == Encipherment::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// создать алгоритм асимметричного шифрования
				return gcnew Keyx::RSA::Encipherment(this, 0); 
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep && oaep) 
			{
				// раскодировать параметры
				ASN1::Sequence^ sequence = gcnew ASN1::Sequence(
					ASN1::Encodable::Decode(parameters->Encoded)
				);
				// проверить параметры по умолчанию
				if (sequence->Length != 0) break; 

				// создать алгоритм асимметричного шифрования
				return gcnew Keyx::RSA::Encipherment(this, CRYPT_OAEP); 
			}
		}
		// для алгоритмов асимметричного шифрования
		else if (type == Decipherment::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// создать алгоритм асимметричного шифрования
				return gcnew Keyx::RSA::Decipherment(this, 0);
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep && oaep) 
			{
				// раскодировать параметры
				ASN1::Sequence^ sequence = gcnew ASN1::Sequence(
					ASN1::Encodable::Decode(parameters->Encoded)
				);
				// проверить параметры по умолчанию
				if (sequence->Length != 0) break; 
					
				// создать алгоритм асимметричного шифрования
				return gcnew Keyx::RSA::Decipherment(this, CRYPT_OAEP); 
			}
		}
		// для алгоритмов подписи
		else if (type == SignHash::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::RSA::SignHash(this);
			}
		}
		// для алгоритмов подписи
		else if (type == VerifyHash::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::RSA::VerifyHash(this);
			}
		}
/*		///////////////////////////////////////////////////////////////////////////
		// не используется из-за ограничений на размер ключа -> 
		// невозможно использовать размер ключа 8 байт, если это не DES-ключ
		// (в DES-ключе присутствуют контрольные биты)
		///////////////////////////////////////////////////////////////////////////
		// для шифрования ключа
		else if (type == TransportKeyWrap::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// создать алгоритм шифрования ключа
				return gcnew Keyx::RSA::TransportKeyWrap(this, 0);
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep)
			{
				// создать алгоритм шифрования ключа
				return gcnew Keyx::RSA::TransportKeyWrap(this, CRYPT_OAEP);
			}
		}
		// для шифрования ключа
		else if (type == TransportKeyUnwrap::typeid)
		{
			// создать алгоритм шифрования ключа
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa)
			{
				// создать алгоритм шифрования ключа
				return gcnew Keyx::RSA::TransportKeyUnwrap(this, 0);
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep)
			{
				// создать алгоритм шифрования ключа
				return gcnew Keyx::RSA::TransportKeyUnwrap(this, CRYPT_OAEP);
			}
		}
*/	}
	// вызвать базовую функцию
	return Microsoft::Provider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}
