#include "..\stdafx.h"
#include "DSSEnhancedProvider.h"
#include "..\SecretKeyType.h"
#include "..\Cipher\RC2.h"
#include "..\Cipher\TDES.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSSEnhancedProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер Enhanced DSS and Diffie-Hellman
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKeyType^
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::EnhancedProvider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// в зависимости от типа алгоритма
	if (Object::ReferenceEquals(keyFactory, Keys::TDES::Instance))
	{
		// указать идентификатор алгоритма
		if (keySize == 24) return gcnew SecretKeyType(CALG_3DES    );
		if (keySize == 16) return gcnew SecretKeyType(CALG_3DES_112);
	}
	// в зависимости от типа алгоритма
	if (Object::ReferenceEquals(keyFactory, Keys::DESX::Instance)) 
	{
		// указать идентификатор алгоритма
		return gcnew SecretKeyType(CALG_DESX); 
	}
	// вызвать базовую функцию
	return DSS::BaseProvider::GetSecretKeyType(keyFactory, keySize); 
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::EnhancedProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, 
	ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type)
{$
	// определить идентификатор алгоритма
	String^ oid = parameters->Algorithm->Value; for (int i = 0; i < 1; i++)
	{
		if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::ANSI::OID::rsa_rc2_ecb)
			{ 
				// указать допустимый размер ключей
				array<int>^ keySizes = KeySizes::Range(5, 16); 

				// при указании параметров алгоритма
				int keyBits = 32; if (!ASN1::Encodable::IsNullOrEmpty(parameters->Parameters))
				{ 
					// раскодировать параметры алгоритма
					ASN1::Integer^ version = gcnew ASN1::Integer(parameters->Parameters);
                
					// определить число битов
					keyBits = ASN1::ANSI::RSA::RC2ParameterVersion::GetKeyBits(version); 
				}
				// проверить число битов
				if (keyBits < 40 || 128 < keyBits) break; 
					
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::RC2(this, keyBits, keySizes)); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_rc2_cbc)
			{
				// указать допустимый размер ключей
				array<int>^ keySizes = KeySizes::Range(5, 16); 

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
				if (keyBits < 40 || 128 < keyBits) break; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::RC2(this, keyBits, keySizes)); 
				
				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(algParameters->IV->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::ssig_tdes_ecb) 
			{
				// указать допустимый размер ключей
				array<int>^ keySizes = gcnew array<int> {16, 24}; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::TDES(this, keySizes)); 

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
				Using<IBlockCipher^> blockCipher(gcnew Cipher::TDES(this, keySizes)); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 
				
				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
		}
	}
    // вызвать базовую функцию
	return BaseProvider::CreateAlgorithm(factory, scope, parameters, type); 
}
