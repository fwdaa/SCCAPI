#include "stdafx.h"
#include "Provider.h"
#include "RSA\RSAEncoding.h"
#include "RSA\RSANPrivateKey.h"
#include "RSA\RSANKeyPairGenerator.h"
#include "X942\X942Encoding.h"
#include "X942\X942NPrivateKey.h"
#include "X942\X942NKeyPairGenerator.h"
#include "X957\X957Encoding.h"
#include "X957\X957NPrivateKey.h"
#include "X957\X957NKeyPairGenerator.h"
#include "X962\X962Encoding.h"
#include "X962\X962NPrivateKey.h"
#include "X962\X962NKeyPairGenerator.h"
#include "Keyx\RSA\PKCS1\RSAPKCS1NEncipherment.h"
#include "Keyx\RSA\PKCS1\RSAPKCS1NDecipherment.h"
#include "Keyx\RSA\OAEP\RSAOAEPNEncipherment.h"
#include "Keyx\RSA\OAEP\RSAOAEPNDecipherment.h"
#include "Keyx\DH\DHNKeyAgreement.h"
#include "Keyx\ECDH\ECDHNKeyAgreement.h"
#include "Sign\RSA\PKCS1\RSAPKCS1NSignHash.h"
#include "Sign\RSA\PKCS1\RSAPKCS1NVerifyHash.h"
#include "Sign\RSA\PSS\RSAPSSNSignHash.h"
#include "Sign\RSA\PSS\RSAPSSNVerifyHash.h"
#include "Sign\DSA\DSANSignHash.h"
#include "Sign\DSA\DSANVerifyHash.h"
#include "Sign\ECDSA\ECDSANSignHash.h"
#include "Sign\ECDSA\ECDSANVerifyHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::Provider(String^ name) 
	
	// ������� ������� ����������
	: CAPI::CNG::NProvider(name), primitiveFactory(gcnew PrimitiveProvider())
{$
	// ������� ������� ����������� ����������
	algs = gcnew Dictionary<DWORD, List<String^>^>();
				
	// ����������� ��������� �������������� ����������
	algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION] = gcnew List<String^>(
		Handle->EnumerateAlgorithms(NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION, NCRYPT_SILENT_FLAG)
	);  
	// ����������� ��������� ������������ �����
	algs[NCRYPT_SECRET_AGREEMENT_OPERATION] = gcnew List<String^>(
		Handle->EnumerateAlgorithms(NCRYPT_SECRET_AGREEMENT_OPERATION, NCRYPT_SILENT_FLAG)
	);  
	// ����������� ��������� �������
	algs[NCRYPT_SIGNATURE_OPERATION] = gcnew List<String^>(
		Handle->EnumerateAlgorithms(NCRYPT_SIGNATURE_OPERATION, NCRYPT_SILENT_FLAG)
	);  
} 

Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::~Provider() 
{$ 
	// ���������� ���������� �������
	delete primitiveFactory; 
}

array<Aladdin::CAPI::KeyFactory^>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::KeyFactories()
{$
	// ������� ������ ������ ������
	List<KeyFactory^>^ keyFactories = gcnew List<KeyFactory^>(); 

	// ��������� ��������� ���������
	if (algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM) || 
		algs[NCRYPT_SIGNATURE_OPERATION            ]->Contains(NCRYPT_RSA_ALGORITHM))
	{
		// �������� ������� ������
		keyFactories->Add(gcnew ANSI::RSA::KeyFactory(ASN1::ISO::PKCS::PKCS1::OID::rsa)); 
	}
	// ��������� ��������� ���������
	if (algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_DH_ALGORITHM))
	{
		// �������� ������� ������
		keyFactories->Add(gcnew ANSI::X942::KeyFactory(ASN1::ANSI::OID::x942_dh_public_key)); 
	}
	// ��������� ��������� ���������
	if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_DSA_ALGORITHM))
	{
		// �������� ������� ������
		keyFactories->Add(gcnew ANSI::X957::KeyFactory(ASN1::ANSI::OID::x957_dsa)); 
	}
	// ��������� ��������� ���������
	if (algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P256_ALGORITHM) || 
		algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P384_ALGORITHM) || 
		algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P521_ALGORITHM) || 
		algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P256_ALGORITHM ) || 
		algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P384_ALGORITHM ) || 
		algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P521_ALGORITHM ))
	{
		// �������� ������� ������
		keyFactories->Add(gcnew ANSI::X962::KeyFactory(ASN1::ANSI::OID::x962_ec_public_key)); 
	}
	// ������� ������ ������
	return keyFactories->ToArray(); 
}

Aladdin::CAPI::CNG::NPrivateKey^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, CAPI::CNG::NKeyHandle^ hKeyPair)
{$
	// ��������� ������������� �����
	if (dynamic_cast<ANSI::RSA::IPublicKey^>(publicKey) != nullptr)
    {
		// ������������� ��� ����������
		ANSI::RSA::IPublicKey^ rsaPublicKey = (ANSI::RSA::IPublicKey^)publicKey;

		// ������� ������ ����
		return gcnew RSA::NPrivateKey(this, scope, rsaPublicKey, hKeyPair); 
    }
	// ��������� ������������� ����������
	if (dynamic_cast<CAPI::ANSI::X942::IPublicKey^>(publicKey) != nullptr) 
	{
		// ������������� ��� ����������
		ANSI::X942::IPublicKey^ dhPublicKey = (ANSI::X942::IPublicKey^)publicKey; 

		// ������� ������ ����
		return gcnew X942::NPrivateKey(this, scope, dhPublicKey, hKeyPair); 
	}
	// ��������� ������������� �����
	if (dynamic_cast<CAPI::ANSI::X957::IPublicKey^>(publicKey) != nullptr) 
	{
		// ������������� ��� ����������
		ANSI::X957::IPublicKey^ dsaPublicKey = (ANSI::X957::IPublicKey^)publicKey; 

		// ������� ������ ����
		return gcnew X957::NPrivateKey(this, scope, dsaPublicKey, hKeyPair); 
    }
	// ��������� ������������� �����
	if (dynamic_cast<CAPI::ANSI::X962::IPublicKey^>(publicKey) != nullptr) 
	{
		// ������������� ��� ����������
		ANSI::X962::IPublicKey^ ecPublicKey = (ANSI::X962::IPublicKey^)publicKey; 

		// ������� ������ ����
		return gcnew X962::NPrivateKey(this, scope, ecPublicKey, hKeyPair); 
    }
	// ������� ������� �������
	return CAPI::CNG::NProvider::GetPrivateKey(scope, publicKey, hKeyPair); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::ExportPublicKey(
	CAPI::CNG::NKeyHandle^ hPublicKey)
{$
	// �������� ������������� ���������
	String^ algID = hPublicKey->GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// ������������� ������ ��������� �����
	if (algID == NCRYPT_RSA_ALGORITHM) return RSA::Encoding::GetPublicKeyInfo(hPublicKey); 

	// ������������� ������ ��������� �����
	if (algID == NCRYPT_DH_ALGORITHM) return X942::Encoding::GetPublicKeyInfo(hPublicKey); 

	// ������������� ������ ��������� �����
	if (algID == NCRYPT_DSA_ALGORITHM) return X957::Encoding::GetPublicKeyInfo(hPublicKey); 

	// ������������� ������ ��������� �����
	if (algID == NCRYPT_ECDSA_P256_ALGORITHM) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDH_P256_ALGORITHM ) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDSA_P384_ALGORITHM) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDH_P384_ALGORITHM ) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDSA_P521_ALGORITHM) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDH_P521_ALGORITHM ) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 

	// ������� ������� �������
	return CAPI::CNG::NProvider::ExportPublicKey(hPublicKey); 
}

Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::ImportPublicKey(
	DWORD keyType, IPublicKey^ publicKey) 
{$
	// ��������� ��� �����
	if (dynamic_cast<CAPI::ANSI::RSA::IPublicKey^>(publicKey) != nullptr) 
	{
		// ���������� ��������� ������ ������
		DWORD cbBlob = RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, 0, 0); 

		// �������� ����� ���������� �������
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

		// �������� ��������� ��� ������� �����
		cbBlob = RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, pbBlob, cbBlob); 

		// ������������� �������� ����
		return Handle->ImportPublicKey(BCRYPT_RSAPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, NCRYPT_SILENT_FLAG); 
	}
	// ��������� ��� �����
	if (dynamic_cast<CAPI::ANSI::X942::IPublicKey^>(publicKey) != nullptr) 
	{
		// ���������� ��������� ������ ������
		DWORD cbBlob = X942::Encoding::GetPublicKeyBlob((ANSI::X942::IPublicKey^)publicKey, 0, 0); 

		// �������� ����� ���������� �������
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DH_KEY_BLOB* pbBlob = (BCRYPT_DH_KEY_BLOB*)&vecBlob[0]; 

		// �������� ��������� ��� ������� �����
		cbBlob = X942::Encoding::GetPublicKeyBlob((ANSI::X942::IPublicKey^)publicKey, pbBlob, cbBlob); 

		// ������������� �������� ����
		return Handle->ImportPublicKey(BCRYPT_DH_PUBLIC_BLOB, IntPtr(pbBlob), cbBlob, NCRYPT_SILENT_FLAG); 
	}
	// ��������� ��� �����
	if (dynamic_cast<CAPI::ANSI::X957::IPublicKey^>(publicKey) != nullptr) 
	{
		// ���������� ��������� ������ ������
		DWORD cbBlob = X957::Encoding::GetPublicKeyBlob((ANSI::X957::IPublicKey^)publicKey, 0, 0); 

		// �������� ����� ���������� �������
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DSA_KEY_BLOB* pbBlob = (BCRYPT_DSA_KEY_BLOB*)&vecBlob[0]; 

		// �������� ��������� ��� ������� �����
		cbBlob = X957::Encoding::GetPublicKeyBlob((ANSI::X957::IPublicKey^)publicKey, pbBlob, cbBlob); 

		// ������������� �������� ����
		return Handle->ImportPublicKey(BCRYPT_DSA_PUBLIC_BLOB, IntPtr(pbBlob), cbBlob, NCRYPT_SILENT_FLAG); 
	}
	// ��������� ��� �����
	if (dynamic_cast<CAPI::ANSI::X962::IPublicKey^>(publicKey) != nullptr) 
	{
		// ������������� ��� ����������
		ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)publicKey->Parameters; 

		// ���������� ��� ���������
		String^ algName = X962::Encoding::GetKeyName(parameters, keyType); 

		// ���������� ��������� ������ ������
		DWORD cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 0, 0); 

		// �������� ����� ���������� �������
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

		// �������� ��������� ��� ������� �����
		cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, pbBlob, cbBlob); 

		// ������������� �������� ����
		return Handle->ImportPublicKey(BCRYPT_ECCPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, NCRYPT_SILENT_FLAG); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException();
}
	
Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::ImportKeyPair(
	CAPI::CNG::Container^ container, IntPtr hwnd, DWORD keyType, BOOL exportable, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	// ��������� ������������� �����
	if (dynamic_cast<ANSI::RSA::IPrivateKey^>(privateKey) != nullptr) 
	{
		// ���������� ��������� ������ ������
		DWORD cbBlob = RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, 0, 0); 

		// �������� ����� ���������� �������
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

		// �������� ��������� ��� ������� �����
		cbBlob = RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, pbBlob, cbBlob); 

		// ������������� ���� ������
		return ImportKeyPair(container, hwnd, nullptr, keyType, 
			BCRYPT_RSAFULLPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, exportable, nullptr, 0
		); 
	}
	// ��������� ������������� �����
	if (dynamic_cast<ANSI::X942::IPrivateKey^>(privateKey) != nullptr) 
	{
		// ���������� ��������� ������ ������
		DWORD cbBlob = X942::Encoding::GetKeyPairBlob((ANSI::X942::IPublicKey^)publicKey, 
			(ANSI::X942::IPrivateKey^)privateKey, 0, 0
		); 
		// �������� ����� ���������� �������
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DH_KEY_BLOB* pbBlob = (BCRYPT_DH_KEY_BLOB*)&vecBlob[0]; 

		// �������� ��������� ��� ������� �����
		cbBlob = X942::Encoding::GetKeyPairBlob((ANSI::X942::IPublicKey^)publicKey, 
			(ANSI::X942::IPrivateKey^)privateKey, pbBlob, cbBlob
		); 
		// ������������� ���� ������
		return ImportKeyPair(container, hwnd, nullptr, keyType, 
			BCRYPT_DH_PRIVATE_BLOB, IntPtr(pbBlob), cbBlob, true, nullptr, 0
		); 
	}
	// ��������� ������������� �����
	if (dynamic_cast<ANSI::X957::IPrivateKey^>(privateKey) != nullptr) 
	{
		// ���������� ��������� ������ ������
		DWORD cbBlob = X957::Encoding::GetKeyPairBlob((ANSI::X957::IPublicKey^)publicKey, 
			(ANSI::X957::IPrivateKey^)privateKey, 0, 0
		); 
		// �������� ����� ���������� �������
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DSA_KEY_BLOB* pbBlob = (BCRYPT_DSA_KEY_BLOB*)&vecBlob[0]; 

		// �������� ��������� ��� ������� �����
		cbBlob = X957::Encoding::GetKeyPairBlob((ANSI::X957::IPublicKey^)publicKey, 
			(ANSI::X957::IPrivateKey^)privateKey, pbBlob, cbBlob
		); 
		// ������������� ���� ������
		return ImportKeyPair(container, hwnd, nullptr, keyType, 
			BCRYPT_DSA_PRIVATE_BLOB, IntPtr(pbBlob), cbBlob, exportable, nullptr, 0
		); 
	}
	// ��������� ������������� �����
	if (dynamic_cast<ANSI::X962::IPrivateKey^>(privateKey) != nullptr) 
	{
		// ������������� ��� ����������
		ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)publicKey->Parameters; 
		
		// ���������� ��� ���������
		String^ algName = X962::Encoding::GetKeyName(parameters, keyType); 

		// ���������� ��������� ������ ������
		DWORD cbBlob = X962::Encoding::GetKeyPairBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 
			(ANSI::X962::IPrivateKey^)privateKey, 0, 0
		); 
		// �������� ����� ���������� �������
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

		// �������� ��������� ��� ������� �����
		cbBlob = X962::Encoding::GetKeyPairBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 
			(ANSI::X962::IPrivateKey^)privateKey, pbBlob, cbBlob
		); 
		// ������������� ���� ������
		return ImportKeyPair(container, hwnd, nullptr, keyType, 
			BCRYPT_ECCPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, exportable, nullptr, 0
		); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::CreateGenerator(
	CAPI::Factory^ factory, SecurityObject^ scope, 
	String^ keyOID, IParameters^ parameters, IRand^ rand)
{$
	// ��������� ��� ����������
	if (keyOID == ASN1::ISO::PKCS::PKCS1::OID::rsa)
	{
		// ������������� ��� ����������
		ANSI::RSA::IParameters^ rsaParameters = (ANSI::RSA::IParameters^)parameters;

		// ��������� �������� ����������
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr;

		// ��������� ��������� ���������
		if (algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM) || 
			algs[NCRYPT_SIGNATURE_OPERATION            ]->Contains(NCRYPT_RSA_ALGORITHM))
		{
			// ������� �������� ��������� ������
			return gcnew RSA::NKeyPairGenerator(this, scope, rand, rsaParameters);
		}
		return nullptr; 
	}
	// ��������� ��� ����������
	if (keyOID == ASN1::ANSI::OID::x942_dh_public_key) 
	{
		// ������������� ��� ����������
		ANSI::X942::IParameters^ dhParameters = (ANSI::X942::IParameters^)parameters; 

		// ��������� ��������� ���������
		if (!algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_DH_ALGORITHM)) return nullptr; 

		// ������� �������� ��������� ������
		return gcnew X942::NKeyPairGenerator(this, scope, rand, dhParameters);
	}
	// ��������� ��� ����������
	if (keyOID == ASN1::ANSI::OID::x957_dsa) 
	{
		// ������������� ��� ����������
		ANSI::X957::IParameters^ dsaParameters = (ANSI::X957::IParameters^)parameters; 

		// ��������� ��������� ���������
		if (!algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_DSA_ALGORITHM)) return nullptr; 

		// ������� �������� ��������� ������
		return gcnew X957::NKeyPairGenerator(this, scope, rand, dsaParameters);
	}
	// ��������� ��� ����������
	if (keyOID == ASN1::ANSI::OID::x962_ec_public_key) 
	{
		// ������������� ��� ����������
		ANSI::X962::IParameters^ ecParameters = (ANSI::X962::IParameters^)parameters; 

		// ��������� ��������� ���������
		if (algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P256_ALGORITHM) || 
			algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P384_ALGORITHM) || 
			algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P521_ALGORITHM) || 
			algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P256_ALGORITHM ) || 
			algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P384_ALGORITHM ) || 
			algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P521_ALGORITHM ))
		{
			// ������� �������� ��������� ������
			return gcnew X962::NKeyPairGenerator(this, scope, rand, ecParameters);
		}
	}
	return nullptr; 
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::CreateAlgorithm(
	CAPI::Factory^ factory, SecurityStore^ scope, 
	ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type)
{$
	// ���������� ������������� ���������
	String^ oid = parameters->Algorithm->Value; for (int i = 0; i < 1; i++)
	{
		// ��� ���������� �����������
		if (type == CAPI::Hash::typeid)
		{
			// ������� �������� ��� ����������
			if (IAlgorithm^ algorithm = ((Factory^)primitiveFactory)->
				CreateAlgorithm<CAPI::Hash^>(scope, parameters)) return algorithm; 
		}
		// ��� ���������� ���������� ������������
		else if (type == Mac::typeid)
		{
			// ������� �������� ��� ����������
			if (IAlgorithm^ algorithm = ((Factory^)primitiveFactory)->
				CreateAlgorithm<Mac^>(scope, parameters)) return algorithm; 
		}
		// ��� ���������� ����������
		else if (type == CAPI::Cipher::typeid)
		{
			// ������� �������� ��� ����������
			if (IAlgorithm^ algorithm = ((Factory^)primitiveFactory)->
				CreateAlgorithm<CAPI::Cipher^>(scope, parameters)) return algorithm; 
		}
		// ��� ���������� �������������� ����������
		else if (type == Encipherment::typeid)
		{
			// ��������� ��������� ���������
			if (algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM))
			{
				// ������� �������� �������������� ����������
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
				{
					// ������� �������� �������������� ����������
					return gcnew Keyx::RSA::PKCS1::NEncipherment(this); 
				}
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) 
				{
					// ������������� ���������
					ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams^ algParameters = 
						gcnew ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams(parameters->Parameters);

					// �������� �������� �����������
					Using<CAPI::Hash^> hashAlgorithm(
						((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
							scope, algParameters->HashAlgorithm
					)); 
					// ��������� ��������� ���������
					if (hashAlgorithm.Get() == nullptr) break;  

					// �������� ������������� ��������� �����������
					String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

					// ���������� ������������� ������������
					String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

					// ��������� ��������� ����������
					if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
					
					// ������������� ��������� ������������
					ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
						gcnew ASN1::ISO::AlgorithmIdentifier(
							algParameters->MaskGenAlgorithm->Parameters
					); 
					// ��������� ���������� ���-���������
					if (maskHashParameters->Algorithm->Value != hashOID) break; 

					// ������� �������� �������������� ����������
					return gcnew Keyx::RSA::OAEP::NEncipherment(
						this, hashOID, algParameters->Label->Value
					);
				}
			}
		}
		// ��� ���������� �������������� ����������
		else if (type == Decipherment::typeid)
		{
			// ��������� ��������� ���������
			if (algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM)) 
			{
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
				{
					// ������� �������� �������������� ����������
					return gcnew Keyx::RSA::PKCS1::NDecipherment(); 
				}
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) 
				{
					// ������������� ���������
					ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams^ algParameters = 
						gcnew ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams(parameters->Parameters);

					// �������� �������� �����������
					Using<CAPI::Hash^> hashAlgorithm(
						((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
							scope, algParameters->HashAlgorithm
					)); 
					// ��������� ��������� ���������
					if (hashAlgorithm.Get() == nullptr) break;  

					// �������� ������������� ��������� �����������
					String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

					// ���������� ������������� ������������
					String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

					// ��������� ��������� ����������
					if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
					
					// ������������� ��������� ������������
					ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
						gcnew ASN1::ISO::AlgorithmIdentifier(
							algParameters->MaskGenAlgorithm->Parameters
					); 
					// ��������� ���������� ���-���������
					if (maskHashParameters->Algorithm->Value != hashOID) break; 

					// ������� �������� �������������� ����������
					return gcnew Keyx::RSA::OAEP::NDecipherment(
						hashOID, algParameters->Label->Value
					);
				}
			}
		}
		// ��� ���������� �������
		else if (type == SignHash::typeid)
		{
			// ��������� ��������� ���������
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM))
			{
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
				{
					// ������� �������� ������� ���-��������
					return gcnew Sign::RSA::PKCS1::NSignHash();
				}
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_pss)
				{
					// ������������� ��������� ���������
					ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams^ algParameters = 
						gcnew ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams(parameters->Parameters); 
 
					// ��������� ��������� ����������
					if (algParameters->TrailerField->Value->IntValue != 0x01) break; 

					// �������� �������� �����������
					Using<CAPI::Hash^> hashAlgorithm(
						((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
							scope, algParameters->HashAlgorithm
					)); 
					// ��������� ��������� ���������
					if (hashAlgorithm.Get() == nullptr) break;  

					// �������� ������������� ��������� �����������
					String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

					// ���������� ������������� ������������
					String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

					// ��������� ��������� ����������
					if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
					
					// ������������� ��������� ������������
					ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
						gcnew ASN1::ISO::AlgorithmIdentifier(
							algParameters->MaskGenAlgorithm->Parameters
					); 
					// ��������� ���������� ���-���������
					if (maskHashParameters->Algorithm->Value != hashOID) break; 

					// ������� �������� ������� ������
					return gcnew Sign::RSA::PSS::NSignHash(
						hashOID, algParameters->SaltLength->IntValue
					);
				}
			}
			// ��������� ��������� ���������
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_DSA_ALGORITHM))
			{
				// ������� �������� ������� ���-��������
				if (oid == ASN1::ANSI::OID::x957_dsa) return gcnew Sign::DSA::NSignHash(); 
			}
			// ��������� ��������� ���������
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P256_ALGORITHM) || 
				algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P384_ALGORITHM) ||
				algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P521_ALGORITHM))
			{
				// ������� �������� ������� ���-��������
				if (oid == ASN1::ANSI::OID::x962_ecdsa_sha1) return gcnew Sign::ECDSA::NSignHash(); 
			}
		}
		// ��� ���������� �������
		else if (type == VerifyHash::typeid)
		{
			// ��������� ��������� ���������
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM))
			{
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
				{
					// ������� �������� ������� ���-��������
					return gcnew Sign::RSA::PKCS1::NVerifyHash(this);
				}
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_pss)
				{
					// ������������� ��������� ���������
					ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams^ algParameters = 
						gcnew ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams(parameters->Parameters); 
 
					// ��������� ��������� ����������
					if (algParameters->TrailerField->Value->IntValue != 0x01) break; 

					// �������� �������� �����������
					Using<CAPI::Hash^> hashAlgorithm(
						((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
							scope, algParameters->HashAlgorithm
					)); 
					// �������� ������������� ��������� �����������
					String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

					// ���������� ������������� ������������
					String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

					// ��������� ��������� ����������
					if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
					
					// ������������� ��������� ������������
					ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
						gcnew ASN1::ISO::AlgorithmIdentifier(
							algParameters->MaskGenAlgorithm->Parameters
					); 
					// ��������� ���������� ���-���������
					if (maskHashParameters->Algorithm->Value != hashOID) break; 

					// ������� �������� ������� ������
					return gcnew Sign::RSA::PSS::NVerifyHash(
						this, hashOID, algParameters->SaltLength->IntValue
					);
				}
			}
			// ��������� ��������� ���������
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_DSA_ALGORITHM))
			{
				// ������� �������� ������� ���-��������
				if (oid == ASN1::ANSI::OID::x957_dsa) return gcnew Sign::DSA::NVerifyHash(this); 
			}
			// ��������� ��������� ���������
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P256_ALGORITHM) || 
				algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P384_ALGORITHM) ||
				algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P521_ALGORITHM))
			{
				// ������� �������� ������� ���-��������
				if (oid == ASN1::ANSI::OID::x962_ecdsa_sha1) return gcnew Sign::ECDSA::NVerifyHash(this); 
			}
		}
		// ��� ���������� �������
		else if (type == SignData::typeid)
		{
			// ������� DSA �������������� ������ ��� SHA1
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_224) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_256) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_512) return nullptr; 
		}
		// ��� ���������� �������� �������
		else if (type == VerifyData::typeid)
		{
			// ������� DSA �������������� ������ ��� SHA1
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_224) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_256) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_512) return nullptr; 
		}
		// ��� ���������� ������������ ������ �����
		else if (type == ITransportAgreement::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS9::OID::smime_ssdh || 
				oid == ASN1::ISO::PKCS::PKCS9::OID::smime_esdh)
			{
    			// ������������� ���������
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1), 
						ASN1::Null::Instance
				); 
				// �������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
   				// ������� �������� ������������ ������ �����
				return gcnew Keyx::DH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters->Algorithm->Value
				); 
			}
			if (oid == ASN1::ISO::PKCS::PKCS9::OID::smime_esdh)
			{
    			// ������������� ���������
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1), 
						ASN1::Null::Instance
				); 
				// �������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// ������� �������� ������������ ������ �����
				return gcnew Keyx::DH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters->Algorithm->Value
				); 
			}
			if (oid == ASN1::ANSI::OID::x963_ecdh_std_sha1)
			{
    			// ������������� ���������
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1), 
						ASN1::Null::Instance
				); 
				// �������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// ������� �������� ������������ ������ �����
				return gcnew Keyx::ECDH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
			if (oid == ASN1::ANSI::OID::certicom_ecdh_std_sha2_256)
			{
    			// ������������� ���������
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_256), 
						ASN1::Null::Instance
				); 
				// �������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// ������� �������� ������������ ������ �����
				return gcnew Keyx::ECDH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
			if (oid == ASN1::ANSI::OID::certicom_ecdh_std_sha2_384)
			{
    			// ������������� ���������
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_384), 
						ASN1::Null::Instance
				); 
				// �������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// ������� �������� ������������ ������ �����
				return gcnew Keyx::ECDH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
			if (oid == ASN1::ANSI::OID::certicom_ecdh_std_sha2_512)
			{
    			// ������������� ���������
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// ������� ��������� ��������� �����������
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_512), 
						ASN1::Null::Instance
				); 
				// �������� �������� �����������
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// ������� �������� ������������ ������ �����
				return gcnew Keyx::ECDH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
		}
	}
	// ������� ������� �������
	return ANSI::Factory::RedirectAlgorithm(factory, scope, parameters, type); 
}
