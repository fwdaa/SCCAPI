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
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������������� Tumar CSP
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKeyType^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// ��������� ��� �����
	if (Object::ReferenceEquals(keyFactory, CAPI::GOST::Keys::GOST::Instance)) 
	{
		// ������� ��� �����
		return gcnew SecretKeyType(CALG_GOST); 
	}
	// ��������� ��� �����
	if (Object::ReferenceEquals(keyFactory, SecretKeyFactory::Generic) && keySize == 32) 
	{
		// ������� ��� �����
		return gcnew SecretKeyType(CALG_GOST); 
	}
	// ������� ������� �������
	return ANSI::CSP::Microsoft::RSA::AESEnhancedProvider::GetSecretKeyType(keyFactory, keySize); 
}

String^ Aladdin::CAPI::KZ::CSP::Tumar::Provider::ConvertKeyOID(ALG_ID keyID)
{$
	// �������� ������������� ���������
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
	// ��� ������ ��������� ����������
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

	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::ImportPublicKey(
	CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType) 
{$
	// ���������� ������������� �����
	String^ keyOID = publicKey->KeyOID; 

	// � ����������� �� ��������������
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_1024     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048     ||
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1024_xch || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536_xch || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048_xch )
	{
		// ������� ������� �������
		return AESEnhancedProvider::ImportPublicKey(hContext, publicKey, keyType); 
	}
	// � ����������� �� ��������������
	if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a     ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b     || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_c     || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a_xch || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
	{
		// ������������ �������� ����
		ASN1::ISO::PKIX::SubjectPublicKeyInfo^ keyInfo = publicKey->Encoded; 

		// �������� �������������� ������������� �����
		array<BYTE>^ blob = keyInfo->SubjectPublicKey->Value; pin_ptr<BYTE> ptrBlob = &blob[0];

		// ������������� �������� ����
		return hContext->ImportKey(nullptr, IntPtr(ptrBlob), blob->Length, 0); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException();
}
 
Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::ExportPublicKey(
	CAPI::CSP::KeyHandle^ hPublicKey)
{$
	// �������� ������������� �����
	String^ keyOID = ConvertKeyOID(hPublicKey->GetLong(KP_ALGID, 0)); 

	// � ����������� �� ��������������
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_1024     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048     ||
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1024_xch || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536_xch || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048_xch )
	{
		// ������� ������� �������
		return AESEnhancedProvider::ExportPublicKey(hPublicKey); 
	}
	// ��� ������ ���� �3410-2001
	if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a	 ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b	 || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_c	 ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a_xch ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
	{
        // ���������� ��������� ������ ������
        DWORD cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0); 

        // �������� ����� ���������� �������
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

		// ��������� �������������� ����
        PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob;

        // ��������� ������� �����
        cbBlob = hPublicKey->Export(hPublicKey, PUBLICKEYBLOB, 0, IntPtr(pBlob), cbBlob);

		// �������� ������ ������
		Array::Resize(blob, cbBlob); 

		// ������������ ��������� �����
		ASN1::ISO::AlgorithmIdentifier^ parameters = gcnew ASN1::ISO::AlgorithmIdentifier(
			gcnew ASN1::ObjectIdentifier(keyOID), ASN1::Null::Instance
		); 
		// ������������ �������� ����
		return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(
			parameters, gcnew ASN1::BitString(blob)
		); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::ImportKeyPair(
	CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	ALG_ID algID = 0; 

	// ��������� ��� �����
	if (dynamic_cast<ANSI::RSA::IPublicKey^>(publicKey) != nullptr)
	{
		// ���������� ����� �����
		switch (((IKeySizeParameters^)publicKey->Parameters)->KeyBits)
		{
		// ������� ������������� �����
		case 1024: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_1024_Xch : CALG_RSA_1024; break;
		case 1536: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_1536_Xch : CALG_RSA_1536; break;
		case 2048: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_2048_Xch : CALG_RSA_2048; break;
		case 3072: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_3072_Xch : CALG_RSA_3072; break;
		case 4096: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_4096_Xch : CALG_RSA_4096; break;

		// ��� ������ ��������� ����������
		default: throw gcnew NotSupportedException(); 
		}
		// ������� ������� �������
		return AESEnhancedProvider::ImportKeyPair(container, algID, keyFlags, publicKey, privateKey); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::CSP::PrivateKey^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType)
{$
	// �������� �������� ����� �����
	array<BYTE>^ keyID = hKeyPair->GetParam(KP_KEY_SN, 0); 

	// ��������� ��� ����������
	if (dynamic_cast<ANSI::RSA::IPublicKey^>(publicKey) != nullptr)
	{
		// ������������� ��� ����������
		ANSI::RSA::IPublicKey^ rsaPublicKey = (ANSI::RSA::IPublicKey^)publicKey;

		// ������� ������ ����
		return gcnew ANSI::CSP::Microsoft::RSA::PrivateKey(
			this, scope, rsaPublicKey, hKeyPair, keyID, keyType);
	}
	// ��������� ��� ����������
	if (dynamic_cast<CAPI::GOST::GOSTR3410::IECPublicKey^>(publicKey) != nullptr)
	{
		// ������������� ��� ����������
		CAPI::GOST::GOSTR3410::IECPublicKey^ gostPublicKey = 
			(CAPI::GOST::GOSTR3410::IECPublicKey^)publicKey; 

		// ������� ������ ����
		return gcnew GOST34310::PrivateKey(
			this, scope, gostPublicKey, hKeyPair, keyID, keyType);
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::KZ::CSP::Tumar::Provider::CreateGenerator(
	CAPI::Factory^ outer, SecurityObject^ scope, 
	IRand^ rand, String^ keyOID, IParameters^ parameters)
{$
	// � ����������� �� ��������������
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_1024     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1024_xch)
	{
		// ������������� ��� ����������
		ANSI::RSA::IParameters^ rsaParameters = ANSI::RSA::Parameters::Convert(parameters);

		// ��������� �������� ����������
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr; 

		// ��������� ������������ ����������
		if (rsaParameters->KeyBits != 1024) throw gcnew ArgumentException(); 

		// ������� �������� ��������� ������
		return gcnew RSA::KeyPairGenerator(this, scope, rand, rsaParameters);
	}
	// � ����������� �� ��������������
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_1536     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_1536_xch)
	{
		// ������������� ��� ����������
		ANSI::RSA::IParameters^ rsaParameters = ANSI::RSA::Parameters::Convert(parameters);

		// ��������� �������� ����������
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr; 

		// ��������� ������������ ����������
		if (rsaParameters->KeyBits != 1536) throw gcnew ArgumentException(); 

		// ������� �������� ��������� ������
		return gcnew RSA::KeyPairGenerator(this, scope, rand, rsaParameters);
	}
	// � ����������� �� ��������������
    if (keyOID == ASN1::KZ::OID::gamma_key_rsa_2048     || 
        keyOID == ASN1::KZ::OID::gamma_key_rsa_2048_xch)
	{
		// ������������� ��� ����������
		ANSI::RSA::IParameters^ rsaParameters = ANSI::RSA::Parameters::Convert(parameters);

		// ��������� �������� ����������
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr; 

		// ��������� ������������ ����������
		if (rsaParameters->KeyBits != 2048) throw gcnew ArgumentException(); 

		// ������� �������� ��������� ������
		return gcnew RSA::KeyPairGenerator(this, scope, rand, rsaParameters);
	}
	// � ����������� �� ��������������
	if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a	 ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b	 || 
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_c	 ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a_xch ||
		keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
	{
		// ������������� ��� ����������
		INamedParameters^ gostParameters = (INamedParameters^)parameters; 

		// ������� ��������� ������
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
		// ��� ���������� �����������
		if (type == CAPI::Hash::typeid)
		{
			// MD2, MD4, MD5 �� ��������������
			if (oid == ASN1::ANSI::OID::rsa_md2) return nullptr;
			if (oid == ASN1::ANSI::OID::rsa_md4) return nullptr;
			if (oid == ASN1::ANSI::OID::rsa_md5) return nullptr;

			// ������� �������� �����������
			if (oid == ASN1::GOST::OID::gostR3411_94) 
			{
				// ��� ��������������� ��������������
				if (parameters->Tag == ASN1::Tag::ObjectIdentifier) 					
				{
					// ������������� ������������� ����������
					oid = ASN1::ObjectIdentifier(parameters).Value;
				}
				// ���������� ������������� �� ���������
				else oid = ASN1::GOST::OID::hashes_cryptopro; 

				// ��� ����������� ������ �����������
				if (oid == ASN1::GOST::OID::hashes_cryptopro)
				{
					// ������� �������� �����������
					return gcnew Hash::GOST34311(this, Handle, CALG_CPGR3411); 
				}
				// ��� ����������� ������ �����������
				if (oid == ASN1::GOST::OID::hashes_test)
				{
					// ������� �������� �����������
					return gcnew Hash::GOST34311(this, Handle, CALG_TGR3411); 
				}
				break;
			}
			if (oid == ASN1::KZ::OID::gamma_gost34311_95) 
			{
				// ������� �������� �����������
				return gcnew Hash::GOST34311(this, Handle, CALG_TGR3411); 
			}
		}
		// ��� ���������� ���������� ������������
		else if (type == Mac::typeid)
		{
			if (oid == ASN1::ANSI::OID::ipsec_hmac_md5) return nullptr;

			// HMAC ����� CSP ����������� ����������� ->
			// ������������ ���������� �� ������ ���-���������
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha1		|| 
				oid == ASN1::ANSI::OID::rsa_hmac_sha2_256	|| 
				oid == ASN1::ANSI::OID::rsa_hmac_sha2_384	|| 
				oid == ASN1::ANSI::OID::rsa_hmac_sha2_512)
			{
				// ������� ������� ����������
				return ANSI::Factory::RedirectAlgorithm(this, scope, oid, parameters, type); 
			}
			if (oid == ASN1::KZ::OID::gamma_hmac_gost34311_95_t)
			{
				// ������� �������� ���������� ������������
				return gcnew MAC::HMAC_GOST34311(this, Handle, CALG_TGR3411_HMAC); 
			}
			if (oid == ASN1::KZ::OID::gamma_hmac_gostR3411_94_cp)
			{
				// ������� �������� ���������� ������������
				return gcnew MAC::HMAC_GOST34311(this, Handle, CALG_CPGR3411_HMAC); 
			}
		}
		// ��� ���������� ������������� ����������
		else if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_ecb)
			{ 
				// ������� ������������� ������� �����������
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// ������� �������� ����������
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// ������� ����� ����������
				CipherMode^ mode = gcnew CipherMode::ECB();
                
				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_cbc)
			{ 
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// ������� ������������� ������� �����������
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// ������� �������� ����������
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// ������� ����� ����������
				CipherMode^ mode = gcnew CipherMode::CBC(iv->Value);
                
				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_cfb || 
				oid == ASN1::KZ::OID::gamma_cipher_gost)
			{ 
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// ������� ������������� ������� �����������
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// ������� �������� ����������
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// ������� ����� ����������
				CipherMode^ mode = gcnew CipherMode::CFB(iv->Value, iv->Value->Length);
                
				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_cnt)
			{ 
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// ������� ������������� ������� �����������
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// ������� �������� ����������
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// ������� ����� ����������
				CipherMode^ mode = gcnew CipherMode::CTR(iv->Value, iv->Value->Length);
                
				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
			if (oid == ASN1::KZ::OID::gamma_cipher_gost_ofb)
			{ 
				// ������������� ��������� ���������
				ASN1::OctetString^ iv = gcnew ASN1::OctetString(parameters); 

				// ������� ������������� ������� �����������
				String^ sboxOID = ASN1::KZ::OID::gamma_gost28147_param_g; 

				// ������� �������� ����������
				Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(this, Handle, sboxOID, false)); 

				// ������� ����� ����������
				CipherMode^ mode = gcnew CipherMode::OFB(iv->Value, iv->Value->Length);
                
				// ������� ����� ����������
				return blockCipher.Get()->CreateBlockMode(mode); 
			}
		}
		// ��� ���������� ����������
		else if (type == Encipherment::typeid)
		{
			// ���������� RSA �� ��������������
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa     ) return nullptr;
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) return nullptr;
		}
		// ��� ���������� ����������
		else if (type == Decipherment::typeid)
		{
			// ���������� RSA �� ��������������
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa     ) return nullptr;
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) return nullptr;
		}
		// ��� ���������� ������� ���-��������
		else if (type == SignHash::typeid)
		{
			// ������� �������� ������� ���-��������
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa   ) return gcnew Sign::RSA::SignHash(this);
			if (oid == ASN1::KZ::OID::gamma_gost34310_2004) 
			{
				// ������� �������� ������� ���-��������
				return gcnew Sign::GOST34310::SignHash(this, CALG_TGR3411);
			}
		}
		// ��� ���������� ������� ���-��������
		else if (type == VerifyHash::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa   ) return gcnew Sign::RSA::VerifyHash(this);
			if (oid == ASN1::KZ::OID::gamma_gost34310_2004) 
			{
				// ������� �������� �������� ������� ���-��������
				return gcnew Sign::GOST34310::VerifyHash(this, CALG_TGR3411);
			}
		}
		// ��� ���������� ������� ���-��������
		else if (type == SignData::typeid)
		{
			// ������� RSA �������������� ������ ��� SHA1 � SHA2-256
	        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_sha2_512) return nullptr; 
		}
		// ��� ���������� ������� ���-��������
		else if (type == VerifyData::typeid)
		{
			// ������� RSA �������������� ������ ��� SHA1 � SHA2-256
	        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_sha2_512) return nullptr; 
		}
		// ��� ���������� ������������ �����
		else if (type == ITransportAgreement::typeid)
		{
			if (oid == ASN1::KZ::OID::gamma_gost28147)
			{
				// ������� �������� ���������� �����
				return gcnew Keyx::GOST34310::TransportAgreement(this, 0); 
			}
		}
		// ��� ���������� ������ �����
		else if (type == TransportKeyWrap::typeid)
		{
			if (oid == ASN1::KZ::OID::gamma_key_ec256_512_a     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_b     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_c     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_a_xch ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
			{
				// ������� �������� ������
				return gcnew Keyx::GOST34310::TransportKeyWrap(this, 0); 
			}
		}
		// ��� ���������� ������ �����
		else if (type == TransportKeyUnwrap::typeid)
		{
			if (oid == ASN1::KZ::OID::gamma_key_ec256_512_a     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_b     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_c     ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_a_xch ||
				oid == ASN1::KZ::OID::gamma_key_ec256_512_b_xch)
			{
				// ������� �������� ������
				return gcnew Keyx::GOST34310::TransportKeyUnwrap(this, 0); 
			}
		}
	}
	// ������� ������� �������
	IAlgorithm^ algorithm = AESEnhancedProvider::CreateAlgorithm(outer, scope, oid, parameters, type); 

	// ��������� ������� ���������
	if (algorithm != nullptr) return algorithm; 

	// ������� ������� �������
	return KZ::Factory::RedirectAlgorithm(outer, scope, oid, parameters, type); 
}
