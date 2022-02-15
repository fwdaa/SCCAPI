#include "..\stdafx.h"
#include "DSSBaseProvider.h"
#include "..\Hash\MD5.h"
#include "..\Hash\SHA1.h"
#include "..\Cipher\RC2.h"
#include "..\Cipher\RC4.h"
#include "..\Cipher\DES.h"
#include "..\Cipher\DESX.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSSBaseProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер Base DSS and Diffie-Hellman
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::BaseProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, 
	ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type)
{$
	// определить идентификатор алгоритма
	String^ oid = parameters->Algorithm->Value; for (int i = 0; i < 1; i++)
	{
		// для алгоритмов хэширования
		if (type == CAPI::Hash::typeid)
		{
			// создать алгоритмы хэширования
			if (oid == ASN1::ANSI::OID::rsa_md5	 ) return gcnew Hash::MD5 (this, Handle);
			if (oid == ASN1::ANSI::OID::ssig_sha1) return gcnew Hash::SHA1(this, Handle);
		}
		else if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::ANSI::OID::rsa_rc2_ecb)
			{ 
				// указать допустимый размер ключей
				array<int>^ keySizes = KeySizes::Range(5, 7); 

				// при указании параметров алгоритма
				int keyBits = 32; if (!ASN1::Encodable::IsNullOrEmpty(parameters->Parameters))
				{ 
					// раскодировать параметры алгоритма
					ASN1::Integer^ version = gcnew ASN1::Integer(parameters->Parameters);
                
					// определить число битов
					keyBits = ASN1::ANSI::RSA::RC2ParameterVersion::GetKeyBits(version); 
				}
				// проверить число битов
				if (keyBits < 40 || 56 < keyBits) break; 
					
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
				array<int>^ keySizes = KeySizes::Range(5, 7); 

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
				if (keyBits < 40 || 56 < keyBits) break; 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::RC2(this, keyBits, keySizes)); 

   				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(algParameters->IV->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_rc4) return gcnew Cipher::RC4(this, KeySizes::Range(5, 7));
			if (oid == ASN1::ANSI::OID::ssig_des_ecb) 
			{
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(this)); 

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
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(this)); 

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
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(this)); 

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
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(this)); 

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
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DESX(this)); 

				// указать используемый режим
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
		}
	}
    // вызвать базовую функцию
	return DSS::Provider::CreateAlgorithm(factory, scope, parameters, type); 
}

