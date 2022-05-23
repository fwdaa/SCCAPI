#include "..\stdafx.h"
#include "AESEnhancedProvider.h"
#include "..\SecretKeyType.h"
#include "..\Hash\SHA2_256.h"
#include "..\Hash\SHA2_384.h"
#include "..\Hash\SHA2_512.h"
#include "..\Cipher\AES.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "AESEnhancedProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������������� AES
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKeyType^
Aladdin::CAPI::CSP::Microsoft::RSA::AESEnhancedProvider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// � ����������� �� ���� ���������
	if (dynamic_cast<ANSI::Keys::AES^>(keyFactory) != nullptr)
	{
		// ������� ������������� ���������
		if (keySize == 32) return gcnew SecretKeyType(CALG_AES_256);
		if (keySize == 24) return gcnew SecretKeyType(CALG_AES_192);
		if (keySize == 16) return gcnew SecretKeyType(CALG_AES_128);
	}
	// ������� ������� �������
	return RSA::EnhancedProvider::GetSecretKeyType(keyFactory, keySize); 
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::CSP::Microsoft::RSA::AESEnhancedProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, String^ oid, 
	ASN1::IEncodable^ parameters, System::Type^ type)
{$
	for (int i = 0; i < 1; i++)
	{
		// ��� ���������� �����������
		if (type == CAPI::Hash::typeid)
		{
			// ��������� ������ Windows
			if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
			{
				// ������� ��������� �����������
				if (oid == ASN1::ANSI::OID::nist_sha2_256) return gcnew Hash::SHA2_256(this, Handle);
				if (oid == ASN1::ANSI::OID::nist_sha2_384) return gcnew Hash::SHA2_384(this, Handle);
				if (oid == ASN1::ANSI::OID::nist_sha2_512) return gcnew Hash::SHA2_512(this, Handle);
			}
		}
		else if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::ANSI::OID::nist_aes128_ecb) 
			{
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {16})); 

				// ������� ����� ���������			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_cbc) 
			{
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {16})); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_ofb) 
			{
				// ������������� ��������� ���������
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// ������� ������ ������
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {16})); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes128_cfb) 
			{
				// ������������� ��������� ���������
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// ������� ������ ������
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {16})); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 
				
				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_ecb) 
			{
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {24})); 

				// ������� ����� ���������			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_cbc) 
			{
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {24})); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_ofb) 
			{
				// ������������� ��������� ���������
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// ������� ������ ������
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {24})); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes192_cfb) 
			{
				// ������������� ��������� ���������
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// ������� ������ ������
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {24})); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_ecb) 
			{
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {32})); 

				// ������� ����� ���������			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_cbc) 
			{
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {32})); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_ofb) 
			{
				// ������������� ��������� ���������
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// ������� ������ ������
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {32})); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::nist_aes256_cfb) 
			{
				// ������������� ��������� ���������
				ASN1::ANSI::FBParameter^ algParameters = 
					gcnew ASN1::ANSI::FBParameter(parameters); 
            
				// ������� ������ ������
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::AES(this, gcnew array<int> {32})); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
		}
	}
    // ������� ������� �������
	return StrongProvider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}


