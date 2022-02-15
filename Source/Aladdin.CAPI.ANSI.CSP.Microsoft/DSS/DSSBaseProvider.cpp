#include "..\stdafx.h"
#include "DSSBaseProvider.h"
#include "..\Hash\MD5.h"
#include "..\Hash\SHA1.h"
#include "..\Cipher\RC2.h"
#include "..\Cipher\RC4.h"
#include "..\Cipher\DES.h"
#include "..\Cipher\DESX.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSSBaseProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������������� Base DSS and Diffie-Hellman
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::BaseProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, 
	ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type)
{$
	// ���������� ������������� ���������
	String^ oid = parameters->Algorithm->Value; for (int i = 0; i < 1; i++)
	{
		// ��� ���������� �����������
		if (type == CAPI::Hash::typeid)
		{
			// ������� ��������� �����������
			if (oid == ASN1::ANSI::OID::rsa_md5	 ) return gcnew Hash::MD5 (this, Handle);
			if (oid == ASN1::ANSI::OID::ssig_sha1) return gcnew Hash::SHA1(this, Handle);
		}
		else if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::ANSI::OID::rsa_rc2_ecb)
			{ 
				// ������� ���������� ������ ������
				array<int>^ keySizes = KeySizes::Range(5, 7); 

				// ��� �������� ���������� ���������
				int keyBits = 32; if (!ASN1::Encodable::IsNullOrEmpty(parameters->Parameters))
				{ 
					// ������������� ��������� ���������
					ASN1::Integer^ version = gcnew ASN1::Integer(parameters->Parameters);
                
					// ���������� ����� �����
					keyBits = ASN1::ANSI::RSA::RC2ParameterVersion::GetKeyBits(version); 
				}
				// ��������� ����� �����
				if (keyBits < 40 || 56 < keyBits) break; 
					
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::RC2(this, keyBits, keySizes)); 

				// ������� ����� ���������			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_rc2_cbc)
			{
				// ������� ���������� ������ ������
				array<int>^ keySizes = KeySizes::Range(5, 7); 

				// ��������� �������� ����������
				if (parameters->Parameters->Tag != ASN1::Tag::Sequence) break; 
				
				// ������������� ��������� ���������
				ASN1::ANSI::RSA::RC2CBCParams^ algParameters = 
					gcnew ASN1::ANSI::RSA::RC2CBCParams(parameters->Parameters);
            
				// ���������� ����� �����
				int keyBits = ASN1::ANSI::RSA::RC2ParameterVersion::GetKeyBits(
					algParameters->ParameterVersion
				); 
				// ��������� ����� �����
				if (keyBits < 40 || 56 < keyBits) break; 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::RC2(this, keyBits, keySizes)); 

   				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CBC(algParameters->IV->Value); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_rc4) return gcnew Cipher::RC4(this, KeySizes::Range(5, 7));
			if (oid == ASN1::ANSI::OID::ssig_des_ecb) 
			{
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(this)); 

				// ������� ����� ���������			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::ssig_des_cbc) 
			{
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters->Parameters); 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(this)); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::ssig_des_ofb) 
			{
				// ������������� ��������� ���������
				ASN1::ANSI::FBParameter^ algParameters = gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 

				// ������� ������ ������
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 
				
				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(this)); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::OFB(algParameters->IV->Value, bits / 8); 
				
				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::ssig_des_cfb) 
			{
				// ������������� ��������� ���������
				ASN1::ANSI::FBParameter^ algParameters = gcnew ASN1::ANSI::FBParameter(parameters->Parameters); 
            
				// ������� ������ ������
				int bits = algParameters->NumberOfBits->Value->IntValue; if ((bits % 8) != 0) break; 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DES(this)); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CFB(algParameters->IV->Value, bits / 8); 
				
				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_desx_cbc) 
			{
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters->Parameters); 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::DESX(this)); 

				// ������� ������������ �����
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
		}
	}
    // ������� ������� �������
	return DSS::Provider::CreateAlgorithm(factory, scope, parameters, type); 
}

