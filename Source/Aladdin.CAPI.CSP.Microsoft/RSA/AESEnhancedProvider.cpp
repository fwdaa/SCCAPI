#include "..\stdafx.h"
#include "AESEnhancedProvider.h"
#include "..\SecretKeyType.h"
#include "..\Hash\SHA2_256.h"
#include "..\Hash\SHA2_384.h"
#include "..\Hash\SHA2_512.h"
#include "..\Cipher\AES.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "AESEnhancedProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер AES
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKeyType^
Aladdin::CAPI::CSP::Microsoft::RSA::AESEnhancedProvider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// в зависимости от типа алгоритма
	if (dynamic_cast<ANSI::Keys::AES^>(keyFactory) != nullptr)
	{
		// указать идентификатор алгоритма
		if (keySize == 32) return gcnew SecretKeyType(CALG_AES_256);
		if (keySize == 24) return gcnew SecretKeyType(CALG_AES_192);
		if (keySize == 16) return gcnew SecretKeyType(CALG_AES_128);
	}
	// вызвать базовую функцию
	return RSA::EnhancedProvider::GetSecretKeyType(keyFactory, keySize); 
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::CSP::Microsoft::RSA::AESEnhancedProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, String^ oid, 
	ASN1::IEncodable^ parameters, System::Type^ type)
{$
	for (int i = 0; i < 1; i++)
	{
		// для алгоритмов хэширования
		if (type == CAPI::Hash::typeid)
		{
			// проверить версию Windows
			if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
			{
				// создать алгоритмы хэширования
				if (oid == ASN1::ANSI::OID::nist_sha2_256) return gcnew Hash::SHA2_256(this, Handle);
				if (oid == ASN1::ANSI::OID::nist_sha2_384) return gcnew Hash::SHA2_384(this, Handle);
				if (oid == ASN1::ANSI::OID::nist_sha2_512) return gcnew Hash::SHA2_512(this, Handle);
			}
		}
		else if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::ANSI::OID::nist_aes128_ecb) 
			{
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {16})); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_cbc) 
			{
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {16})); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_ofb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {16})); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_cfb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {16})); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 
				
				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_ecb) 
			{
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {24})); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_cbc) 
			{
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {24})); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_ofb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {24})); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_cfb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {24})); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_ecb) 
			{
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {32})); 

				// указать режим алгоритма			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_cbc) 
			{
				// раскодировать параметры алгоритма
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {32})); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_ofb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {32})); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_cfb) 
			{
				// раскодировать параметры алгоритма
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// извлечь размер сдвига
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// создать алгоритм шифрования 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {32})); 

				// указать режим алгоритма
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 

				// вернуть режим шифрования
				return blockCipher.Get()->CreateBlockMode(mode);
			}
		}
	}
    // вызвать базовую функцию
	return StrongProvider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}


