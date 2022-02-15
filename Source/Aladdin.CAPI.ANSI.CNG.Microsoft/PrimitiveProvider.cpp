#include "stdafx.h"
#include "PrimitiveProvider.h"
#include "RSA\RSABKeyPairGenerator.h"
#include "X942\X942BKeyPairGenerator.h"
#include "X957\X957BKeyPairGenerator.h"
#include "X962\X962BKeyPairGenerator.h"
#include "Hash\MD2.h"
#include "Hash\MD4.h"
#include "Hash\MD5.h"
#include "Hash\SHA1.h"
#include "Hash\SHA2_256.h"
#include "Hash\SHA2_384.h"
#include "Hash\SHA2_512.h"
#include "MAC\HMAC.h"
#include "MAC\AES_CMAC.h"
#include "Cipher\RC2.h"
#include "Cipher\RC4.h"
#include "Cipher\DES.h"
#include "Cipher\DESX.h"
#include "Cipher\TDES.h"
#include "Cipher\AES.h"
#include "Keyx\RSA\PKCS1\RSAPKCS1BEncipherment.h"
#include "Keyx\RSA\PKCS1\RSAPKCS1BDecipherment.h"
#include "Keyx\RSA\OAEP\RSAOAEPBEncipherment.h"
#include "Keyx\RSA\OAEP\RSAOAEPBDecipherment.h"
#include "Keyx\DH\DHBKeyAgreement.h"
#include "Keyx\ECDH\ECDHBKeyAgreement.h"
#include "Sign\RSA\PKCS1\RSAPKCS1BSignHash.h"
#include "Sign\RSA\PKCS1\RSAPKCS1BVerifyHash.h"
#include "Sign\RSA\PSS\RSAPSSBSignHash.h"
#include "Sign\RSA\PSS\RSAPSSBVerifyHash.h"
#include "Sign\DSA\DSABSignHash.h"
#include "Sign\DSA\DSABVerifyHash.h"
#include "Sign\ECDSA\ECDSABSignHash.h"
#include "Sign\ECDSA\ECDSABVerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "PrimitiveProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Microsoft Primitive Provider
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::PrimitiveProvider::CreateGenerator(
	CAPI::Factory^ factory, SecurityObject^ scope, 
	String^ keyOID, IParameters^ parameters, IRand^ rand)
{$
	if (keyOID == ASN1::ISO::PKCS::PKCS1::OID::rsa)
	{
		// преобразовать тип параметров
		ANSI::RSA::IParameters^ rsaParameters = (ANSI::RSA::IParameters^)parameters;

		// проверить значение экспоненты
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr;

		// вернуть алгоритм генерации
		return gcnew RSA::BKeyPairGenerator(factory, scope, rand, Provider, rsaParameters); 
	}
	if (keyOID == ASN1::ANSI::OID::x942_dh_public_key) 
	{
		// преобразовать тип параметров
		ANSI::X942::IParameters^ dhParameters = (ANSI::X942::IParameters^)parameters; 

		// вернуть алгоритм генерации
		return gcnew X942::BKeyPairGenerator(factory, scope, rand, Provider, dhParameters); 
	}
	if (keyOID == ASN1::ANSI::OID::x957_dsa) 
	{
		// преобразовать тип параметров
		ANSI::X957::IParameters^ dsaParameters = (ANSI::X957::IParameters^)parameters; 

		// вернуть алгоритм генерации
		return gcnew X957::BKeyPairGenerator(factory, scope, rand, Provider, dsaParameters); 
	}
	if (keyOID == ASN1::ANSI::OID::x962_ec_public_key) 
	{
		// преобразовать тип параметров
		ANSI::X962::IParameters^ ecParameters = (ANSI::X962::IParameters^)parameters; 

		// вернуть алгоритм генерации
		return gcnew X962::BKeyPairGenerator(factory, scope, rand, Provider, ecParameters); 
	}
	return nullptr; 
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::PrimitiveProvider::CreateAlgorithm(
	CAPI::Factory^ factory, SecurityStore^ scope, 
	ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type)
{$
	// определить идентификатор алгоритма
	String^ oid = parameters->Algorithm->Value; for (int i = 0; i < 1; i++)
	{
		// для алгоритмов хэширования
		if (type == CAPI::Hash::typeid)
		{
			// создать алгоритмы хэширования
			if (oid == ASN1::ANSI::OID::rsa_md2	     ) return gcnew Hash::MD2     (Provider);
			if (oid == ASN1::ANSI::OID::rsa_md4	     ) return gcnew Hash::MD4     (Provider);
			if (oid == ASN1::ANSI::OID::rsa_md5	     ) return gcnew Hash::MD5     (Provider);
			if (oid == ASN1::ANSI::OID::ssig_sha1    ) return gcnew Hash::SHA1    (Provider);
			if (oid == ASN1::ANSI::OID::nist_sha2_256) return gcnew Hash::SHA2_256(Provider);
			if (oid == ASN1::ANSI::OID::nist_sha2_384) return gcnew Hash::SHA2_384(Provider);
			if (oid == ASN1::ANSI::OID::nist_sha2_512) return gcnew Hash::SHA2_512(Provider);
		}
		else if (type == Mac::typeid)
		{
			if (oid == ASN1::ANSI::OID::ipsec_hmac_md5)
			{
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(Provider, BCRYPT_MD5_ALGORITHM, 64); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha1)
			{
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(Provider, BCRYPT_SHA1_ALGORITHM, 64); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha2_256)
			{
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(Provider, BCRYPT_SHA256_ALGORITHM, 64); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha2_384)
			{
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(Provider, BCRYPT_SHA384_ALGORITHM, 128); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha2_512)
			{
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC(Provider, BCRYPT_SHA512_ALGORITHM, 128); 
			}
		}
		else if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::ANSI::OID::rsa_rc2_ecb)
			{ 
				// указать допустимый размер ключей
				array<int>^ keySizes = KeySizes::Range(1, 16); 

				// при указании параметров алгоритма
				int keyBits = 32; if (!ASN1::Encodable::IsNullOrEmpty(parameters->Parameters))
				{ 
					// раскодировать параметры алгоритма
					ASN1::Integer^ version = gcnew ASN1::Integer(parameters->Parameters);
                
					// определить число битов
					keyBits = ASN1::ANSI::RSA::RC2ParameterVersion::GetKeyBits(version); 
				}
				// проверить число битов
				if (keyBits < 8 || 128 < keyBits) break; 
					
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::RC2(Provider, keyBits, keySizes)); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 
				
				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_rc2_cbc)
			{
				// указать допустимый размер ключей
				array<int>^ keySizes = KeySizes::Range(1, 16); 

				// проверить указание параметров
				if (parameters->Parameters->Tag != ASN1::Tag::Sequence) break; 
				
				// раскодировать параметры алгоритма
				ASN1::ANSI::RSA::RC2CBCParams^ algParameters = 
					gcnew ASN1::ANSI::RSA::RC2CBCParams(parameters->Parameters);
            
				// определить число битов
				int keyBits = ASN1::ANSI::RSA::RC2ParameterVersion::GetKeyBits(
					algParameters->ParameterVersion
				); 
				// проверить число битов
				if (keyBits < 8 || 128 < keyBits) break; 
				
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::RC2(Provider, keyBits, keySizes)); 

   				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(algParameters->IV->Value); 
				
				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_rc4) 
			{
				// вернуть алгоритм шифрования
				return gcnew Cipher::RC4(Provider, KeySizes::Range(1, 16));
			}
			if (oid == ASN1::ANSI::OID::ssig_des_ecb) 
			{
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(Provider)); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::ssig_des_cbc) 
			{
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters->Parameters); 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(Provider)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::ssig_des_ofb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 

				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(Provider)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 
				
				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::ssig_des_cfb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(Provider)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 
				
				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_desx_cbc) 
			{
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters->Parameters); 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DESX(Provider)); 

				// указать используемый режим
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::ssig_tdes_ecb) 
			{
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {16, 24}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::TDES(Provider, keySizes)); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_tdes192_cbc) 
			{
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters->Parameters); 

				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {24}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::TDES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 
				
				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_ecb) 
			{
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {16}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_cbc) 
			{
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters->Parameters); 

				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {16}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_ofb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {16}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_cfb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {16}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_ecb) 
			{
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {24}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_cbc) 
			{
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters->Parameters); 

				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {24}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_ofb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {24}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_cfb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {24}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_ecb) 
			{
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {32}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_cbc) 
			{
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters->Parameters); 

				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {32}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_ofb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {32}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_cfb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {32}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(Provider, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
		}
		// для алгоритмов асимметричного шифрования
		else if (type == Encipherment::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{ 
				// создать алгоритм асимметричного шифрования
				return gcnew Keyx::RSA::PKCS1::BEncipherment(Provider); 
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) 
			{
				// раскодировать параметры
				ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams^ algParameters = 
					gcnew ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams(parameters->Parameters);

				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((CAPI::Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
						scope, algParameters->HashAlgorithm
				)); 
				// проверить поддержку алгоритма
				if (hashAlgorithm.Get() == nullptr) break; 

				// получить идентификатор алгоритма хэширования
				String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

				// определить идентификатор маскирования
				String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

				// проверить поддержку параметров
				if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
				
				// раскодировать параметры маскирования
				ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						algParameters->MaskGenAlgorithm->Parameters
				); 
				// проверить совпадение хэш-алгоритма
				if (maskHashParameters->Algorithm->Value != hashOID) break; 
				
				// создать алгоритм асимметричного шифрования
				return gcnew Keyx::RSA::OAEP::BEncipherment(
					Provider, hashOID, algParameters->Label->Value
				); 
			}
		}
		// для алгоритмов асимметричного шифрования
		else if (type == Decipherment::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{ 
				// создать алгоритм асимметричного шифрования
				return gcnew Keyx::RSA::PKCS1::BDecipherment(Provider); 
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) 
			{
				// раскодировать параметры
				ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams^ algParameters = 
					gcnew ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams(parameters->Parameters);

				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((CAPI::Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
						scope, algParameters->HashAlgorithm
				)); 
				// проверить поддержку алгоритма
				if (hashAlgorithm.Get() == nullptr) break; 

				// получить идентификатор алгоритма хэширования
				String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

				// определить идентификатор маскирования
				String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

				// проверить поддержку параметров
				if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
				
				// раскодировать параметры маскирования
				ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						algParameters->MaskGenAlgorithm->Parameters
				); 
				// проверить совпадение хэш-алгоритма
				if (maskHashParameters->Algorithm->Value != hashOID) break; 
				
				// создать алгоритм асимметричного шифрования
				return gcnew Keyx::RSA::OAEP::BDecipherment(
					Provider, hashOID, algParameters->Label->Value
				);
			}
		}
		// для алгоритмов подписи
		else if (type == SignHash::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::RSA::PKCS1::BSignHash(Provider);
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_pss)
			{
				// раскодировать параметры алгоритма
				ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams^ algParameters = 
					gcnew ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams(parameters->Parameters); 

				// проверить поддержку алгоритма
				if (algParameters->TrailerField->Value->IntValue != 0x01) break; 
 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(factory->CreateAlgorithm<CAPI::Hash^>(
					scope, algParameters->HashAlgorithm
				)); 
				// проверить поддержку алгоритма
				if (hashAlgorithm.Get() == nullptr) break; 

				// получить идентификатор алгоритма хэширования
				String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

				// определить идентификатор маскирования
				String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

				// проверить поддержку параметров
				if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
				
				// раскодировать параметры маскирования
				ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						algParameters->MaskGenAlgorithm->Parameters
				); 
				// проверить совпадение хэш-алгоритма
				if (maskHashParameters->Algorithm->Value != hashOID) break; 

				// создать алгоритм подписи хэш-значения
				return gcnew Sign::RSA::PSS::BSignHash(
					Provider, hashOID, algParameters->SaltLength->IntValue
				);
			}
			if (oid == ASN1::ANSI::OID::x957_dsa       ) return gcnew Sign::  DSA::BSignHash(Provider); 
			if (oid == ASN1::ANSI::OID::x962_ecdsa_sha1) return gcnew Sign::ECDSA::BSignHash(Provider); 
		}
		// для алгоритмов подписи
		else if (type == VerifyHash::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::RSA::PKCS1::BVerifyHash(Provider);
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_pss)
			{
				// раскодировать параметры алгоритма
				ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams^ algParameters = 
					gcnew ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams(parameters->Parameters); 
 
				// проверить поддержку алгоритма
				if (algParameters->TrailerField->Value->IntValue != 0x01) break; 

				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(factory->CreateAlgorithm<CAPI::Hash^>(
					scope, algParameters->HashAlgorithm
				)); 
				// проверить поддержку алгоритма
				if (hashAlgorithm.Get() == nullptr) break; 

				// получить идентификатор алгоритма хэширования
				String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

				// определить идентификатор маскирования
				String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

				// проверить поддержку параметров
				if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
				
				// раскодировать параметры маскирования
				ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						algParameters->MaskGenAlgorithm->Parameters
				); 
				// проверить совпадение хэш-алгоритма
				if (maskHashParameters->Algorithm->Value != hashOID) break; 

				// создать алгоритм подписи хэш-значения
				return gcnew Sign::RSA::PSS::BVerifyHash(
					Provider, hashOID, algParameters->SaltLength->IntValue
				);
			}
			if (oid == ASN1::ANSI::OID::x957_dsa       ) return gcnew Sign::  DSA::BVerifyHash(Provider); 
			if (oid == ASN1::ANSI::OID::x962_ecdsa_sha1) return gcnew Sign::ECDSA::BVerifyHash(Provider); 
		}
		// для алгоритмов подписи
		else if (type == SignData::typeid)
		{
			// подпись DSA поддерживается только для SHA1
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_224) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_256) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_512) return nullptr; 
		}
		// для алгоритмов проверки подписи
		else if (type == VerifyData::typeid)
		{
			// подпись DSA поддерживается только для SHA1
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_224) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_256) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_512) return nullptr; 
		}
		// для алгоритмов согласования общего ключа
		else if (type == IKeyAgreement::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS9::OID::smime_ssdh || 
				oid == ASN1::ISO::PKCS::PKCS9::OID::smime_esdh)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((CAPI::Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм согласования общего ключа
				return gcnew Keyx::DH::BKeyAgreement(
					Provider, (CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters->Algorithm->Value
				); 
			}
			if (oid == ASN1::ANSI::OID::x963_ecdh_std_sha1)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((CAPI::Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::ECDH::BKeyAgreement(
					Provider, (CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
			if (oid == ASN1::ANSI::OID::certicom_ecdh_std_sha2_256)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_256), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((CAPI::Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::ECDH::BKeyAgreement(
					Provider, (CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
			if (oid == ASN1::ANSI::OID::certicom_ecdh_std_sha2_384)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_384), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((CAPI::Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::ECDH::BKeyAgreement(
					Provider, (CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
			if (oid == ASN1::ANSI::OID::certicom_ecdh_std_sha2_512)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_512), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((CAPI::Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::ECDH::BKeyAgreement(
					Provider, (CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
		}
	}
	// вызвать базовую функцию
	return ANSI::Factory::RedirectAlgorithm(factory, scope, parameters, type); 
}
