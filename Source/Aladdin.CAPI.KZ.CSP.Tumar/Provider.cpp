#include "stdafx.h"
#include "Provider.h"
#include "SecretKeyType.h"
#include "RSA\RSAKeyPairGenerator.h"
#include "GOST34310\GOST34310PrivateKey.h"
#include "GOST34310\GOST34310KeyPairGenerator.h"
#include "Hash\GOST34311.h"
#include "MAC\HMAC_GOST34311.h"
#include "MAC\MAC_GOST28147.h"
#include "Cipher\GOST28147.h"
#include "Sign\RSA\RSASignHash.h"
#include "Sign\RSA\RSAVerifyHash.h"
#include "Sign\GOST34310\GOST34310SignHash.h"
#include "Sign\GOST34310\GOST34310VerifyHash.h"
#include "Keyx\GOST34310\GOST34310TransportAgreement.h"
#include "Keyx\GOST34310\GOST34310TransportKeyWrap.h"
#include "Keyx\GOST34310\GOST34310TransportKeyUnwrap.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер Tumar CSP
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKeyType^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// проверить тип ключа
	if (Object::ReferenceEquals(keyFactory, CAPI::GOST::Keys::GOST::Instance)) 
	{
		// вернуть тип ключа
		return gcnew SecretKeyType(CALG_GOST); 
	}
	// проверить тип ключа
	if (Object::ReferenceEquals(keyFactory, SecretKeyFactory::Generic) && keySize == 32) 
	{
		// вернуть тип ключа
		return gcnew SecretKeyType(CALG_GOST); 
	}
	// вызвать базовую функцию
	return ANSI::CSP::Microsoft::RSA::AESEnhancedProvider::GetSecretKeyType(keyFactory, keySize); 
}

String^ Aladdin::CAPI::KZ::CSP::Tumar::Provider::ConvertKeyOID(ALG_ID keyID)
{$
	// получить идентификатор алгоритма
	switch (keyID)
	{
	case CALG_RSA_1024        : return ASN1::KZ::OID::gamma_key_rsa_1024       ;  
	case CALG_RSA_1536        : return ASN1::KZ::OID::gamma_key_rsa_1536       ; 
	case CALG_RSA_2048        : return ASN1::KZ::OID::gamma_key_rsa_2048       ; 
	case CALG_RSA_3072        : return ASN1::KZ::OID::gamma_key_rsa_3072       ; 
	case CALG_RSA_4096        : return ASN1::KZ::OID::gamma_key_rsa_4096       ; 
	case CALG_RSA_1024_Xch    : return ASN1::KZ::OID::gamma_key_rsa_1024_xch   ; 
	case CALG_RSA_1536_Xch    : return ASN1::KZ::OID::gamma_key_rsa_1536_xch   ; 
	case CALG_RSA_2048_Xch    : return ASN1::KZ::OID::gamma_key_rsa_2048_xch   ; 
	case CALG_RSA_3072_Xch    : return ASN1::KZ::OID::gamma_key_rsa_3072_xch   ; 
	case CALG_RSA_4096_Xch    : return ASN1::KZ::OID::gamma_key_rsa_4096_xch   ; 
	case CALG_EC256_512G_A    : return ASN1::KZ::OID::gamma_key_ec256_512_a    ;  
	case CALG_EC256_512G_B    : return ASN1::KZ::OID::gamma_key_ec256_512_b    ; 
	case CALG_EC256_512G_C    : return ASN1::KZ::OID::gamma_key_ec256_512_c    ; 
	case CALG_EC256_512G_A_Xch: return ASN1::KZ::OID::gamma_key_ec256_512_a_xch; 
	case CALG_EC256_512G_B_Xch: return ASN1::KZ::OID::gamma_key_ec256_512_b_xch; 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException();
}

ALG_ID Aladdin::CAPI::KZ::CSP::Tumar::Provider::ConvertKeyOID(String^ keyID, DWORD keyType)
{$
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_1024       ) return CALG_RSA_1024; 
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_1536       ) return CALG_RSA_1536; 
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_2048       ) return CALG_RSA_2048; 
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_3072       ) return CALG_RSA_3072; 
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_4096       ) return CALG_RSA_4096; 
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_1024_xch   ) return CALG_RSA_1024_Xch; 
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_1536_xch   ) return CALG_RSA_1536_Xch; 
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_2048_xch   ) return CALG_RSA_2048_Xch; 
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_3072_xch   ) return CALG_RSA_3072_Xch; 
	if (keyID == ASN1::KZ::OID::gamma_key_rsa_4096_xch   ) return CALG_RSA_4096_Xch; 
	if (keyID == ASN1::KZ::OID::gamma_key_ec256_512_a    ) return CALG_EC256_512G_A; 
	if (keyID == ASN1::KZ::OID::gamma_key_ec256_512_b    ) return CALG_EC256_512G_B; 
	if (keyID == ASN1::KZ::OID::gamma_key_ec256_512_c    ) return CALG_EC256_512G_C; 
	if (keyID == ASN1::KZ::OID::gamma_key_ec256_512_a_xch) return CALG_EC256_512G_A_Xch; 
	if (keyID == ASN1::KZ::OID::gamma_key_ec256_512_b_xch) return CALG_EC256_512G_B_Xch; 

	// при ошибке выбросить исключение
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::ImportPublicKey(
	CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType) 
{$
	// определить идентификатор ключа
	String^ keyOID = publicKey->KeyOID; 

	// в зависимости от идентификатора
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_1024     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048     ||
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1024_xch || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536_xch || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048_xch )
	{
		// вызвать базовую функцию
		return AESEnhancedProvider::ImportPublicKey(hContext, publicKey, keyType); 
	}
	// в зависимости от идентификатора
	if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a     ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b     || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_c     || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a_xch || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
	{
		// закодировать открытый ключ
		ASN1::ISO::PKIX::SubjectPublicKeyInfo^ keyInfo = publicKey->Encoded; 

		// получить закодированное представление ключа
		array<BYTE>^ blob = keyInfo->SubjectPublicKey->Value; pin_ptr<BYTE> ptrBlob = &blob[0];

		// импортировать открытый ключ
		return hContext->ImportKey(nullptr, IntPtr(ptrBlob), blob->Length, 0); 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException();
}
 
Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::ExportPublicKey(
	CAPI::CSP::KeyHandle^ hPublicKey)
{$
	// получить идентификатор ключа
	String^ keyOID = ConvertKeyOID(hPublicKey->GetLong(KP_ALGID, 0)); 

	// в зависимости от идентификатора
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_1024     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048     ||
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1024_xch || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536_xch || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048_xch )
	{
		// вызвать базовую функцию
		return AESEnhancedProvider::ExportPublicKey(hPublicKey); 
	}
	// для ключей ГОСТ Р3410-2001
	if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a	 ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b	 || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_c	 ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a_xch ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
	{
        // определить требуемый размер буфера
        DWORD cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0); 

        // выделить буфер требуемого размера
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

		// выполнить преобразование типа
        PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob;

        // выполнить экспорт ключа
        cbBlob = hPublicKey->Export(hPublicKey, PUBLICKEYBLOB, 0, IntPtr(pBlob), cbBlob);

		// изменить размер буфера
		Array::Resize(blob, cbBlob); 

		// закодировать параметры ключа
		ASN1::ISO::AlgorithmIdentifier^ parameters = gcnew ASN1::ISO::AlgorithmIdentifier(
			gcnew ASN1::ObjectIdentifier(keyOID), ASN1::Null::Instance
		); 
		// закодировать открытый ключ
		return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(
			parameters, gcnew ASN1::BitString(blob)
		); 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::ImportKeyPair(
	CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	ALG_ID algID = 0; 

	// проверить тип ключа
	if (dynamic_cast<ANSI::RSA::IPublicKey^>(publicKey) != nullptr)
	{
		// определить число битов
		switch (((IKeySizeParameters^)publicKey->Parameters)->KeyBits)
		{
		// указать идентификатор ключа
		case 1024: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_1024_Xch : CALG_RSA_1024; break;
		case 1536: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_1536_Xch : CALG_RSA_1536; break;
		case 2048: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_2048_Xch : CALG_RSA_2048; break;
		case 3072: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_3072_Xch : CALG_RSA_3072; break;
		case 4096: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_4096_Xch : CALG_RSA_4096; break;

		// при ошибке выбросить исключение
		default: throw gcnew NotSupportedException(); 
		}
		// вызвать базовую функцию
		return AESEnhancedProvider::ImportKeyPair(container, algID, keyFlags, publicKey, privateKey); 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::CSP::PrivateKey^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType)
{$
	// получить серийный номер ключа
	array<BYTE>^ keyID = hKeyPair->GetParam(KP_KEY_SN, 0); 

	// проверить тип параметров
	if (dynamic_cast<ANSI::RSA::IPublicKey^>(publicKey) != nullptr)
	{
		// преобразовать тип параметров
		ANSI::RSA::IPublicKey^ rsaPublicKey = (ANSI::RSA::IPublicKey^)publicKey;

		// создать личный ключ
		return gcnew ANSI::CSP::Microsoft::RSA::PrivateKey(
			this, scope, rsaPublicKey, hKeyPair, keyID, keyType);
	}
	// проверить тип параметров
	if (dynamic_cast<CAPI::GOST::GOSTR3410::IECPublicKey^>(publicKey) != nullptr)
	{
		// преобразовать тип параметров
		CAPI::GOST::GOSTR3410::IECPublicKey^ gostPublicKey = 
			(CAPI::GOST::GOSTR3410::IECPublicKey^)publicKey; 

		// создать личный ключ
		return gcnew GOST34310::PrivateKey(
			this, scope, gostPublicKey, hKeyPair, keyID, keyType);
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::CreateGenerator(
	CAPI::Factory^ outer, SecurityObject^ scope, 
	IRand^ rand, String^ keyOID, IParameters^ parameters)
{$
	// в зависимости от идентификатора
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_1024     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1024_xch)
	{
		// преобразовать тип параметров
		ANSI::RSA::IParameters^ rsaParameters = ANSI::RSA::Parameters::Convert(parameters);

		// проверить значение экспоненты
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr; 

		// проверить корректность параметров
		if (rsaParameters->KeyBits != 1024) throw gcnew ArgumentException(); 

		// создать алгоритм генерации ключей
		return gcnew RSA::KeyPairGenerator(this, scope, rand, rsaParameters);
	}
	// в зависимости от идентификатора
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_1536     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536_xch)
	{
		// преобразовать тип параметров
		ANSI::RSA::IParameters^ rsaParameters = ANSI::RSA::Parameters::Convert(parameters);

		// проверить значение экспоненты
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr; 

		// проверить корректность параметров
		if (rsaParameters->KeyBits != 1536) throw gcnew ArgumentException(); 

		// создать алгоритм генерации ключей
		return gcnew RSA::KeyPairGenerator(this, scope, rand, rsaParameters);
	}
	// в зависимости от идентификатора
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_2048     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048_xch)
	{
		// преобразовать тип параметров
		ANSI::RSA::IParameters^ rsaParameters = ANSI::RSA::Parameters::Convert(parameters);

		// проверить значение экспоненты
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr; 

		// проверить корректность параметров
		if (rsaParameters->KeyBits != 2048) throw gcnew ArgumentException(); 

		// создать алгоритм генерации ключей
		return gcnew RSA::KeyPairGenerator(this, scope, rand, rsaParameters);
	}
	// в зависимости от идентификатора
	if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a	 ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b	 || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_c	 ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a_xch ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
	{
		// преобразовать тип параметров
		INamedParameters^ gostParameters = (INamedParameters^)parameters; 

		// создать генератор ключей
		return gcnew GOST34310::KeyPairGenerator(this, scope, rand, gostParameters); 
	}
	return nullptr; 
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::CreateAlgorithm(
	CAPI::Factory^ outer, SecurityStore^ scope, 
	String^ oid, ASN1::IEncodable^ parameters, System::Type^ type)
{$
	for (int i = 0; i < 1; i++)
	{
		// для алгоритмов хэширования
		if (type == CAPI::Hash::typeid)
		{
			// MD2, MD4, MD5 не поддерживаются
			if (oid == ASN1::ANSI::OID::rsa_md2) return nullptr;
			if (oid == ASN1::ANSI::OID::rsa_md4) return nullptr;
			if (oid == ASN1::ANSI::OID::rsa_md5) return nullptr;

			// вернуть алгоритм хэширования
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

				// для специальных таблиц прдстановок
				if (oid == ASN1::GOST::OID::hashes_cryptopro)
				{
					// создать алгоритм хэширования
					return gcnew Hash::GOST34311(this, Handle, CALG_CPGR3411); 
				}
				// для специальных таблиц прдстановок
				if (oid == ASN1::GOST::OID::hashes_test)
				{
					// создать алгоритм хэширования
					return gcnew Hash::GOST34311(this, Handle, CALG_TGR3411); 
				}
				break;
			}
			if (oid == ASN1::KZ::OID::gamma_gost34311_95) 
			{
				// создать алгоритм хэширования
				return gcnew Hash::GOST34311(this, Handle, CALG_TGR3411); 
			}
		}
		// для алгоритмов вычисления имитовставки
		else if (type == Mac::typeid)
		{
			if (oid == ASN1::ANSI::OID::ipsec_hmac_md5) return nullptr;

			// HMAC через CSP вычисляется неправильно ->
			// используется реализация на основе хэш-алгоритма
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha1		|| 
				oid == ASN1::ANSI::OID::rsa_hmac_sha2_256	|| 
				oid == ASN1::ANSI::OID::rsa_hmac_sha2_384	|| 
				oid == ASN1::ANSI::OID::rsa_hmac_sha2_512)
			{
				// вызвать базовую реализацию
				return ANSI::Factory::RedirectAlgorithm(this, scope, oid, parameters, type); 
			}
			if (oid == ASN1::KZ::OID::gamma_hmac_gost34311_95_t)
			{
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC_GOST34311(this, Handle, CALG_TGR3411_HMAC); 
			}
			if (oid == ASN1::KZ::OID::gamma_hmac_gostR3411_94_cp)
			{
				// создать алгоритм вычисления имитовставки
				return gcnew MAC::HMAC_GOST34311(this, Handle, CALG_CPGR3411_HMAC); 
			}
		}
		// для алгоритмов симметричного шифрования
		else if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_ecb)
			{ 
				// указать идентификатор таблицы подстановок
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// создать алгоритм шифрования
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// указать режим шифрования
				CipherMode^ mode = gcnew CipherMode::ECB();
                
				// создать режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_cbc)
			{ 
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// указать идентификатор таблицы подстановок
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// создать алгоритм шифрования
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// указать режим шифрования
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value);
                
				// создать режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_cfb || 
				oid == ASN1::KZ::OID::gamma_cipher_gost)
			{ 
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// указать идентификатор таблицы подстановок
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// создать алгоритм шифрования
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// указать режим шифрования
				CipherMode^ mode = gcnew CipherMode::CFB(iv->Value, iv->Value->Length);
                
				// создать режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_cnt)
			{ 
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// указать идентификатор таблицы подстановок
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// создать алгоритм шифрования
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// указать режим шифрования
				CipherMode^ mode = gcnew CipherMode::CTR(iv->Value, iv->Value->Length);
                
				// создать режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_ofb)
			{ 
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// указать идентификатор таблицы подстановок
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// создать алгоритм шифрования
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// указать режим шифрования
				CipherMode^ mode = gcnew CipherMode::OFB(iv->Value, iv->Value->Length);
                
				// создать режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
		}
		// для алгоритмов шифрования
		else if (type == Encipherment::typeid)
		{
			// шифрование RSA не поддерживается
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa     ) return nullptr;
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) return nullptr;
		}
		// для алгоритмов шифрования
		else if (type == Decipherment::typeid)
		{
			// шифрование RSA не поддерживается
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa     ) return nullptr;
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) return nullptr;
		}
		// для алгоритмов подписи хэш-значения
		else if (type == SignHash::typeid)
		{
			// создать алгоритм подписи хэш-значения
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa   ) return gcnew Sign::RSA::SignHash(this);
			if (oid == ASN1::KZ::OID::gamma_gost34310_2004) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::GOST34310::SignHash(this, CALG_TGR3411);
			}
		}
		// для алгоритмов подписи хэш-значения
		else if (type == VerifyHash::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa   ) return gcnew Sign::RSA::VerifyHash(this);
			if (oid == ASN1::KZ::OID::gamma_gost34310_2004) 
			{
				// создать алгоритм проверки подписи хэш-значения
				return gcnew Sign::GOST34310::VerifyHash(this, CALG_TGR3411);
			}
		}
		// для алгоритмов подписи хэш-значения
		else if (type == SignData::typeid)
		{
			// подпись RSA поддерживается только для SHA1 и SHA2-256
	        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_sha2_512) return nullptr; 
		}
		// для алгоритмов подписи хэш-значения
		else if (type == VerifyData::typeid)
		{
			// подпись RSA поддерживается только для SHA1 и SHA2-256
	        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_sha2_512) return nullptr; 
		}
		// для алгоритмов согласования ключа
		else if (type == ITransportAgreement::typeid)
		{
			if (oid == ASN1::KZ::OID::gamma_gost28147)
			{
				// вернуть алгоритм шифрования ключа
				return gcnew Keyx::GOST34310::TransportAgreement(this, 0); 
			}
		}
		// для алгоритмов обмена ключа
		else if (type == TransportKeyWrap::typeid)
		{
			if (oid == ASN1::KZ::OID::gamma_key_ec256_512_a     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_b     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_c     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_a_xch ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
			{
				// создать алгоритм обмена
				return gcnew Keyx::GOST34310::TransportKeyWrap(this, 0); 
			}
		}
		// для алгоритмов обмена ключа
		else if (type == TransportKeyUnwrap::typeid)
		{
			if (oid == ASN1::KZ::OID::gamma_key_ec256_512_a     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_b     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_c     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_a_xch ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
			{
				// создать алгоритм обмена
				return gcnew Keyx::GOST34310::TransportKeyUnwrap(this, 0); 
			}
		}
	}
	// вызвать базовую функцию
	IAlgorithm^ algorithm = AESEnhancedProvider::CreateAlgorithm(outer, scope, oid, parameters, type); 

	// проверить наличие алгоритма
	if (algorithm != nullptr) return algorithm; 

	// вызвать базовую функцию
	return KZ::Factory::RedirectAlgorithm(outer, scope, oid, parameters, type); 
}
