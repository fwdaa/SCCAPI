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
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������������� RSA
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKeyType^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// � ����������� �� ���� ���������
	if (dynamic_cast<Keys::DES^>(keyFactory) != nullptr) 
	{
		// ������� ������������� ���������
		return gcnew SecretKeyType(CALG_DES); 
	}
	// � ����������� �� ���� ���������
	if (dynamic_cast<Keys::RC4^>(keyFactory) != nullptr) 
	{
		// ������� ������������� ���������
		return gcnew SecretKeyType(CALG_RC4);
	}
	// � ����������� �� ���� ���������
	if (dynamic_cast<Keys::RC2^>(keyFactory) != nullptr) 
	{
		// ������� ������������� ���������
		return gcnew SecretKeyType(CALG_RC2);
	}
	// ������� ������������� ��������� �� ���������
	return gcnew SecretKeyType(CALG_RC2); 
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::ImportKeyPair(
	CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	ALG_ID algID = keyType; 

	// ���������� ������������� ���������
	if (keyType == AT_KEYEXCHANGE) algID = CALG_RSA_KEYX; else 
	if (keyType == AT_SIGNATURE  ) algID = CALG_RSA_SIGN; 

	// ������������� ��� ������
	ANSI::RSA::IPublicKey^  rsaPublicKey  = (ANSI::RSA::IPublicKey ^)publicKey; 
	ANSI::RSA::IPrivateKey^ rsaPrivateKey = (ANSI::RSA::IPrivateKey^)privateKey; 

	// ������� �������� ���������� � ������
	Math::BigInteger^ exponent = rsaPublicKey->PublicExponent; 
	Math::BigInteger^ modvalue = rsaPublicKey->Modulus; 

	// ��������� ������ ����������
	if (exponent > Math::BigInteger::ValueOf(UInt32::MaxValue)) throw gcnew InvalidDataException();

	// ������������ �������� ������
	array<BYTE>^ modulus = Math::Convert::FromBigInteger(modvalue, Endian); 

	// ������� ������������� ���������
	PUBLICKEYSTRUC header = { PRIVATEKEYBLOB, CUR_BLOB_VERSION, 0, algID }; 

	// ������� ��������� RSA
	RSAPUBKEY headerRSA = { 0x32415352, (UINT)modvalue->BitLength, (DWORD)exponent->LongValue }; 

	// ������� ������ � ��������� ������� �����
	array<BYTE>^ prime1       = Math::Convert::FromBigInteger(rsaPrivateKey->PrimeP         , Endian);
	array<BYTE>^ prime2       = Math::Convert::FromBigInteger(rsaPrivateKey->PrimeQ         , Endian); 
	array<BYTE>^ exponent1    = Math::Convert::FromBigInteger(rsaPrivateKey->PrimeExponentP , Endian);
	array<BYTE>^ exponent2    = Math::Convert::FromBigInteger(rsaPrivateKey->PrimeExponentQ , Endian);
	array<BYTE>^ coefficient  = Math::Convert::FromBigInteger(rsaPrivateKey->CrtCoefficient , Endian);
	array<BYTE>^ privExponent = Math::Convert::FromBigInteger(rsaPrivateKey->PrivateExponent, Endian);

	// ���������� �������� ������ � ���������
	DWORD ofs = sizeof(header) + sizeof(headerRSA); DWORD cb = headerRSA.bitlen / 16; 

	// �������� ������ ��� ��������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(ofs + 9 * cb); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 

	// ����������� ������������� ��������� � ��������� RSA
	*pBlob = header; *(RSAPUBKEY*)(pBlob + 1) = headerRSA; 

	// ����������� �������� ������ � �������� �����
	Array::Copy(modulus     , 0, blob, ofs + 0 * cb, modulus     ->Length);
	Array::Copy(prime1      , 0, blob, ofs + 2 * cb, prime1      ->Length); 
	Array::Copy(prime2      , 0, blob, ofs + 3 * cb, prime2      ->Length); 
	Array::Copy(exponent1   , 0, blob, ofs + 4 * cb, exponent1   ->Length); 
	Array::Copy(exponent2   , 0, blob, ofs + 5 * cb, exponent2   ->Length); 
	Array::Copy(coefficient , 0, blob, ofs + 6 * cb, coefficient ->Length); 
	Array::Copy(privExponent, 0, blob, ofs + 7 * cb, privExponent->Length); 

	// ������������� ���� ������
	return ImportKey(container, nullptr, IntPtr(ptrBlob), blob->Length, keyFlags); 
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::ImportPublicKey(
	CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType)
{$
	// ������������� ������������� �����
	ALG_ID algID = ConvertKeyOID(publicKey->KeyOID, keyType); 

	// ������������� ��� �����
	ANSI::RSA::IPublicKey^ rsaPublicKey = (ANSI::RSA::IPublicKey^)publicKey; 

	// ������� �������� ���������� � ������
	Math::BigInteger^ exponent = rsaPublicKey->PublicExponent; 
	Math::BigInteger^ modvalue = rsaPublicKey->Modulus; 

	// ��������� ������ ����������
	if (exponent > Math::BigInteger::ValueOf(UInt32::MaxValue)) throw gcnew InvalidDataException();

	// ������������ �������� ������
	array<BYTE>^ modulus = Math::Convert::FromBigInteger(modvalue, Endian); 

	// ������� ������������� ���������
	PUBLICKEYSTRUC header = { PUBLICKEYBLOB, CUR_BLOB_VERSION, 0, algID }; 

	// ������� ��������� RSA
	RSAPUBKEY headerRSA = { 0x31415352, (UINT)modvalue->BitLength, (DWORD)exponent->LongValue }; 

	// ���������� �������� ������ � ���������
	DWORD ofs = sizeof(header) + sizeof(headerRSA); DWORD cb = headerRSA.bitlen / 16; 

	// �������� ������ ��� ��������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(ofs + 2 * cb); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 

	// ����������� ������������� ��������� � ��������� RSA
	*pBlob = header; *(RSAPUBKEY*)(pBlob + 1) = headerRSA; 

	// ����������� �������� ������
	Array::Copy(modulus, 0, blob, ofs, modulus->Length);

	// ������������� ���� ������
	return hContext->ImportKey(nullptr, IntPtr(ptrBlob), blob->Length, 0); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::ExportPublicKey(
	CAPI::CSP::KeyHandle^ hPublicKey)
{$
	// ������� ������������� �����
	String^ keyOID = ConvertKeyOID(hPublicKey->GetLong(KP_ALGID, 0)); 

	// ���������� ������ ������
	DWORD cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0);

	// �������� ������ ��� ��������� ��������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; RSAPUBKEY* pInfo = (RSAPUBKEY*)(pBlob + 1); 

	// �������������� �������� ����
	cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr(pBlob), cbBlob);

	// �������� ������ ��� ������
	array<BYTE>^ buffer = gcnew array<BYTE>(pInfo->bitlen / 8);

	// ����������� �������� ������
	Array::Copy(blob, sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY), buffer, 0, buffer->Length); 

	// ������������� �������� ������
	Math::BigInteger^ modulus = Math::Convert::ToBigInteger(buffer, Endian);  

	// ������������ �������� ����
	ASN1::ISO::PKCS::PKCS1::RSAPublicKey^ encoded = 
		gcnew ASN1::ISO::PKCS::PKCS1::RSAPublicKey(
			gcnew ASN1::Integer(modulus), gcnew ASN1::Integer(pInfo->pubexp)
	); 
	// ������������ ��������� ���������
	ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
            gcnew ASN1::ObjectIdentifier(keyOID), 
            ASN1::Null::Instance
    ); 
	// �������� �������������� ������������� �����
	ASN1::BitString^ encodedKey = gcnew ASN1::BitString(encoded->Encoded); 

	// ������� �������������� ���� � ���������
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
}
		
Aladdin::CAPI::CSP::PrivateKey^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType)
{$
	// ��������� ������������� ����������
	if (dynamic_cast<ANSI::RSA::IPublicKey^>(publicKey) != nullptr)
    {
		// ������������� ��� ����������
		ANSI::RSA::IPublicKey^ rsaPublicKey = (ANSI::RSA::IPublicKey^)publicKey;

		// ������� ������������� �����
		array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

		// ������� ������ ����
		return gcnew RSA::PrivateKey(this, scope, rsaPublicKey, hKeyPair, keyID, keyType); 
    }
	// ������� ������� �������
	return CAPI::CSP::Provider::GetPrivateKey(scope, publicKey, hKeyPair, keyType); 
}

Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::Provider::CreateGenerator(
	Factory^ factory, SecurityObject^ scope, 
	IRand^ rand, String^ keyOID, IParameters^ parameters)
{$
	// ������� ������������� ���������
	keyOID = CAPI::ANSI::Factory::RedirectKeyName(keyOID); 

	// ��������� ������������� ����������
	if (keyOID == ASN1::ISO::PKCS::PKCS1::OID::rsa)
	{
		// ������������� ��� ����������
		ANSI::RSA::IParameters^ rsaParameters = ANSI::RSA::Parameters::Convert(parameters);

		// ��������� �������� ����������
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr; 
		
		// ������� �������� ��������� ������
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
				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::rsa_md5), 
						ASN1::Null::Instance
				); 
				// ������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// ��������� ��� ���������
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break; 
				
				// ������� �������� ���������� ������������
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha1)
			{
				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1),
						ASN1::Null::Instance
				); 
				// ������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// ��������� ��� ���������
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break; 
				
				// ������� �������� ���������� ������������
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha2_256)
			{
				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_256), 
						ASN1::Null::Instance
				); 
				// ������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// ��������� ��� ���������
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break; 
				
				// ������� �������� ���������� ������������
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha2_384)
			{
				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_384), 
						ASN1::Null::Instance
				); 
				// ������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// ��������� ��� ���������
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break; 
				
				// ������� �������� ���������� ������������
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
			if (oid == ASN1::ANSI::OID::rsa_hmac_sha2_512)
			{
				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_512), 
						ASN1::Null::Instance
				); 
				// ������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				);  
				// ��������� ��� ���������
				if (dynamic_cast<CAPI::CSP::Hash^>(hashAlgorithm.Get()) == nullptr) break;
				
				// ������� �������� ���������� ������������
				return gcnew MAC::HMAC(this, (CAPI::CSP::Hash^)hashAlgorithm.Get()); 
			}
		}
		// ��� ���������� �������������� ����������
		else if (type == Encipherment::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// ������� �������� �������������� ����������
				return gcnew Keyx::RSA::Encipherment(this, 0); 
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep && oaep) 
			{
				// ������������� ���������
				ASN1::Sequence^ sequence = gcnew ASN1::Sequence(
					ASN1::Encodable::Decode(parameters->Encoded)
				);
				// ��������� ��������� �� ���������
				if (sequence->Length != 0) break; 

				// ������� �������� �������������� ����������
				return gcnew Keyx::RSA::Encipherment(this, CRYPT_OAEP); 
			}
		}
		// ��� ���������� �������������� ����������
		else if (type == Decipherment::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// ������� �������� �������������� ����������
				return gcnew Keyx::RSA::Decipherment(this, 0);
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep && oaep) 
			{
				// ������������� ���������
				ASN1::Sequence^ sequence = gcnew ASN1::Sequence(
					ASN1::Encodable::Decode(parameters->Encoded)
				);
				// ��������� ��������� �� ���������
				if (sequence->Length != 0) break; 
					
				// ������� �������� �������������� ����������
				return gcnew Keyx::RSA::Decipherment(this, CRYPT_OAEP); 
			}
		}
		// ��� ���������� �������
		else if (type == SignHash::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// ������� �������� ������� ���-��������
				return gcnew Sign::RSA::SignHash(this);
			}
		}
		// ��� ���������� �������
		else if (type == VerifyHash::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// ������� �������� ������� ���-��������
				return gcnew Sign::RSA::VerifyHash(this);
			}
		}
/*		///////////////////////////////////////////////////////////////////////////
		// �� ������������ ��-�� ����������� �� ������ ����� -> 
		// ���������� ������������ ������ ����� 8 ����, ���� ��� �� DES-����
		// (� DES-����� ������������ ����������� ����)
		///////////////////////////////////////////////////////////////////////////
		// ��� ���������� �����
		else if (type == TransportKeyWrap::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
			{
				// ������� �������� ���������� �����
				return gcnew Keyx::RSA::TransportKeyWrap(this, 0);
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep)
			{
				// ������� �������� ���������� �����
				return gcnew Keyx::RSA::TransportKeyWrap(this, CRYPT_OAEP);
			}
		}
		// ��� ���������� �����
		else if (type == TransportKeyUnwrap::typeid)
		{
			// ������� �������� ���������� �����
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa)
			{
				// ������� �������� ���������� �����
				return gcnew Keyx::RSA::TransportKeyUnwrap(this, 0);
			}
			if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep)
			{
				// ������� �������� ���������� �����
				return gcnew Keyx::RSA::TransportKeyUnwrap(this, CRYPT_OAEP);
			}
		}
*/	}
	// ������� ������� �������
	return Microsoft::Provider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}
