#include "..\stdafx.h"
#include "DSSEnhancedProvider.h"
#include "..\SecretKeyType.h"
#include "..\Cipher\RC2.h"
#include "..\Cipher\RC4.h"
#include "..\Cipher\TDES.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSSEnhancedProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������������� Enhanced DSS and Diffie-Hellman
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKeyType^
Aladdin::CAPI::CSP::Microsoft::DSS::EnhancedProvider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// � ����������� �� ���� ���������
	if (dynamic_cast<ANSI::Keys::TDES^>(keyFactory) != nullptr)
	{
		// ������� ������������� ���������
		if (keySize == 24) return gcnew SecretKeyType(CALG_3DES    );
		if (keySize == 16) return gcnew SecretKeyType(CALG_3DES_112);
	}
	// � ����������� �� ���� ���������
	if (dynamic_cast<ANSI::Keys::DESX^>(keyFactory) != nullptr) 
	{
		// ������� ������������� ���������
		return gcnew SecretKeyType(CALG_DESX); 
	}
	// ������� ������� �������
	return DSS::BaseProvider::GetSecretKeyType(keyFactory, keySize); 
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::CSP::Microsoft::DSS::EnhancedProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, String^ oid, 
	ASN1::IEncodable^ parameters, System::Type^ type)
{$
	for (int i = 0; i < 1; i++)
	{
		if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::ANSI::OID::rsa_rc2_ecb)
			{ 
				// ������� ���������� ������ ������
				array<int>^ keySizes = KeySizes::Range(5, 16); 

				// ��� �������� ���������� ���������
				int keyBits = 32; if (!ASN1::Encodable::IsNullOrEmpty(parameters))
				{ 
					// ������������� ��������� ���������
					ASN1::Integer^ version = gcnew ASN1::Integer(parameters);
                
					// ���������� ����� �����
					keyBits = ASN1::ANSI::RSA::RC2ParameterVersion::GetKeyBits(version); 
				}
				// ��������� ����� �����
				if (keyBits < 40 || 128 < keyBits) break; 
					
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
				array<int>^ keySizes = KeySizes::Range(5, 16); 

				// ��������� �������� ����������
				if (parameters->Tag != ASN1::Tag::Sequence) break; 
				
				// ������������� ��������� ���������
				ASN1::ANSI::RSA::RC2CBCParams^ algParameters = 
					gcnew ASN1::ANSI::RSA::RC2CBCParams(parameters);
            
				// ���������� ����� �����
				int keyBits = ASN1::ANSI::RSA::RC2ParameterVersion::GetKeyBits(
					algParameters->ParameterVersion
				); 
				// ��������� ����� �����
				if (keyBits < 40 || 128 < keyBits) break; 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::RC2(this, keyBits, keySizes)); 
				
				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CBC(algParameters->IV->Value); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_rc4) return gcnew Cipher::RC4(this, KeySizes::Range(5, 16));
			if (oid == ASN1::ANSI::OID::ssig_tdes_ecb) 
			{
				// ������� ���������� ������ ������
				array<int>^ keySizes = gcnew array<int> {16, 24}; 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::TDES(this, keySizes)); 

				// ������� ����� ���������			
				CipherMode^ mode = gcnew CipherMode::ECB(); 

				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
			if (oid == ASN1::ANSI::OID::rsa_tdes192_cbc) 
			{
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// ������� ���������� ������ ������
				array<int>^ keySizes = gcnew array<int> {24}; 

				// ������� �������� ���������� 
				Using<IBlockCipher^> blockCipher(gcnew Cipher::TDES(this, keySizes)); 

				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value); 
				
				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode);
			}
		}
	}
    // ������� ������� �������
	return BaseProvider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}
