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
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::Provider(String^ name) 
	
	// создать фабрику алгоритмов
	: CAPI::CNG::NProvider(name), primitiveFactory(gcnew PrimitiveProvider())
{$
	// создать фабрику программных алгоритмов
	algs = gcnew Dictionary<DWORD, List<String^>^>();
				
	// перечислить алгоритмы асимметричного шифрования
	algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION] = gcnew List<String^>(
		Handle->EnumerateAlgorithms(NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION, NCRYPT_SILENT_FLAG)
	);  
	// перечислить алгоритмы согласования ключа
	algs[NCRYPT_SECRET_AGREEMENT_OPERATION] = gcnew List<String^>(
		Handle->EnumerateAlgorithms(NCRYPT_SECRET_AGREEMENT_OPERATION, NCRYPT_SILENT_FLAG)
	);  
	// перечислить алгоритмы подписи
	algs[NCRYPT_SIGNATURE_OPERATION] = gcnew List<String^>(
		Handle->EnumerateAlgorithms(NCRYPT_SIGNATURE_OPERATION, NCRYPT_SILENT_FLAG)
	);  
} 

Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::~Provider() 
{$ 
	// освободить выделенные ресурсы
	delete primitiveFactory; 
}

array<Aladdin::CAPI::KeyFactory^>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::KeyFactories()
{$
	// создать список фабрик ключей
	List<KeyFactory^>^ keyFactories = gcnew List<KeyFactory^>(); 

	// проверить поддержку алгоритма
	if (algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM) || 
		algs[NCRYPT_SIGNATURE_OPERATION            ]->Contains(NCRYPT_RSA_ALGORITHM))
	{
		// добавить фабрику ключей
		keyFactories->Add(gcnew ANSI::RSA::KeyFactory(ASN1::ISO::PKCS::PKCS1::OID::rsa)); 
	}
	// проверить поддержку алгоритма
	if (algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_DH_ALGORITHM))
	{
		// добавить фабрику ключей
		keyFactories->Add(gcnew ANSI::X942::KeyFactory(ASN1::ANSI::OID::x942_dh_public_key)); 
	}
	// проверить поддержку алгоритма
	if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_DSA_ALGORITHM))
	{
		// добавить фабрику ключей
		keyFactories->Add(gcnew ANSI::X957::KeyFactory(ASN1::ANSI::OID::x957_dsa)); 
	}
	// проверить поддержку алгоритма
	if (algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P256_ALGORITHM) || 
		algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P384_ALGORITHM) || 
		algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P521_ALGORITHM) || 
		algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P256_ALGORITHM ) || 
		algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P384_ALGORITHM ) || 
		algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P521_ALGORITHM ))
	{
		// добавить фабрику ключей
		keyFactories->Add(gcnew ANSI::X962::KeyFactory(ASN1::ANSI::OID::x962_ec_public_key)); 
	}
	// вернуть список фабрик
	return keyFactories->ToArray(); 
}

Aladdin::CAPI::CNG::NPrivateKey^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, CAPI::CNG::NKeyHandle^ hKeyPair)
{$
	// проверить идентификатор ключа
	if (dynamic_cast<ANSI::RSA::IPublicKey^>(publicKey) != nullptr)
    {
		// преобразовать тип параметров
		ANSI::RSA::IPublicKey^ rsaPublicKey = (ANSI::RSA::IPublicKey^)publicKey;

		// создать личный ключ
		return gcnew RSA::NPrivateKey(this, scope, rsaPublicKey, hKeyPair); 
    }
	// проверить идентификатор параметров
	if (dynamic_cast<CAPI::ANSI::X942::IPublicKey^>(publicKey) != nullptr) 
	{
		// преобразовать тип параметров
		ANSI::X942::IPublicKey^ dhPublicKey = (ANSI::X942::IPublicKey^)publicKey; 

		// создать личный ключ
		return gcnew X942::NPrivateKey(this, scope, dhPublicKey, hKeyPair); 
	}
	// проверить идентификатор ключа
	if (dynamic_cast<CAPI::ANSI::X957::IPublicKey^>(publicKey) != nullptr) 
	{
		// преобразовать тип параметров
		ANSI::X957::IPublicKey^ dsaPublicKey = (ANSI::X957::IPublicKey^)publicKey; 

		// создать личный ключ
		return gcnew X957::NPrivateKey(this, scope, dsaPublicKey, hKeyPair); 
    }
	// проверить идентификатор ключа
	if (dynamic_cast<CAPI::ANSI::X962::IPublicKey^>(publicKey) != nullptr) 
	{
		// преобразовать тип параметров
		ANSI::X962::IPublicKey^ ecPublicKey = (ANSI::X962::IPublicKey^)publicKey; 

		// создать личный ключ
		return gcnew X962::NPrivateKey(this, scope, ecPublicKey, hKeyPair); 
    }
	// вызвать базовую функцию
	return CAPI::CNG::NProvider::GetPrivateKey(scope, publicKey, hKeyPair); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::ExportPublicKey(
	CAPI::CNG::NKeyHandle^ hPublicKey)
{$
	// получить идентификатор алгоритма
	String^ algID = hPublicKey->GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// преобразовать формат открытого ключа
	if (algID == NCRYPT_RSA_ALGORITHM) return RSA::Encoding::GetPublicKeyInfo(hPublicKey); 

	// преобразовать формат открытого ключа
	if (algID == NCRYPT_DH_ALGORITHM) return X942::Encoding::GetPublicKeyInfo(hPublicKey); 

	// преобразовать формат открытого ключа
	if (algID == NCRYPT_DSA_ALGORITHM) return X957::Encoding::GetPublicKeyInfo(hPublicKey); 

	// преобразовать формат открытого ключа
	if (algID == NCRYPT_ECDSA_P256_ALGORITHM) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDH_P256_ALGORITHM ) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDSA_P384_ALGORITHM) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDH_P384_ALGORITHM ) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDSA_P521_ALGORITHM) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 
	if (algID == NCRYPT_ECDH_P521_ALGORITHM ) return X962::Encoding::GetPublicKeyInfo(hPublicKey); 

	// вызвать базовую функцию
	return CAPI::CNG::NProvider::ExportPublicKey(hPublicKey); 
}

Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::ImportPublicKey(
	DWORD keyType, IPublicKey^ publicKey) 
{$
	// проверить тип ключа
	if (dynamic_cast<CAPI::ANSI::RSA::IPublicKey^>(publicKey) != nullptr) 
	{
		// определить требуемый размер буфера
		DWORD cbBlob = RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, 0, 0); 

		// выделить буфер требуемого размера
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

		// получить структуру для импорта ключа
		cbBlob = RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, pbBlob, cbBlob); 

		// импортировать открытый ключ
		return Handle->ImportPublicKey(BCRYPT_RSAPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, NCRYPT_SILENT_FLAG); 
	}
	// проверить тип ключа
	if (dynamic_cast<CAPI::ANSI::X942::IPublicKey^>(publicKey) != nullptr) 
	{
		// определить требуемый размер буфера
		DWORD cbBlob = X942::Encoding::GetPublicKeyBlob((ANSI::X942::IPublicKey^)publicKey, 0, 0); 

		// выделить буфер требуемого размера
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DH_KEY_BLOB* pbBlob = (BCRYPT_DH_KEY_BLOB*)&vecBlob[0]; 

		// получить структуру для импорта ключа
		cbBlob = X942::Encoding::GetPublicKeyBlob((ANSI::X942::IPublicKey^)publicKey, pbBlob, cbBlob); 

		// импортировать открытый ключ
		return Handle->ImportPublicKey(BCRYPT_DH_PUBLIC_BLOB, IntPtr(pbBlob), cbBlob, NCRYPT_SILENT_FLAG); 
	}
	// проверить тип ключа
	if (dynamic_cast<CAPI::ANSI::X957::IPublicKey^>(publicKey) != nullptr) 
	{
		// определить требуемый размер буфера
		DWORD cbBlob = X957::Encoding::GetPublicKeyBlob((ANSI::X957::IPublicKey^)publicKey, 0, 0); 

		// выделить буфер требуемого размера
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DSA_KEY_BLOB* pbBlob = (BCRYPT_DSA_KEY_BLOB*)&vecBlob[0]; 

		// получить структуру для импорта ключа
		cbBlob = X957::Encoding::GetPublicKeyBlob((ANSI::X957::IPublicKey^)publicKey, pbBlob, cbBlob); 

		// импортировать открытый ключ
		return Handle->ImportPublicKey(BCRYPT_DSA_PUBLIC_BLOB, IntPtr(pbBlob), cbBlob, NCRYPT_SILENT_FLAG); 
	}
	// проверить тип ключа
	if (dynamic_cast<CAPI::ANSI::X962::IPublicKey^>(publicKey) != nullptr) 
	{
		// преобразовать тип параметров
		ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)publicKey->Parameters; 

		// определить имя алгоритма
		String^ algName = X962::Encoding::GetKeyName(parameters, keyType); 

		// определить требуемый размер буфера
		DWORD cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 0, 0); 

		// выделить буфер требуемого размера
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

		// получить структуру для импорта ключа
		cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, pbBlob, cbBlob); 

		// импортировать открытый ключ
		return Handle->ImportPublicKey(BCRYPT_ECCPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, NCRYPT_SILENT_FLAG); 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException();
}
	
Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::ImportKeyPair(
	CAPI::CNG::Container^ container, IntPtr hwnd, DWORD keyType, BOOL exportable, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	// проверить идентификатор ключа
	if (dynamic_cast<ANSI::RSA::IPrivateKey^>(privateKey) != nullptr) 
	{
		// определить требуемый размер буфера
		DWORD cbBlob = RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, 0, 0); 

		// выделить буфер требуемого размера
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

		// получить структуру для импорта ключа
		cbBlob = RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, pbBlob, cbBlob); 

		// импортировать пару ключей
		return ImportKeyPair(container, hwnd, nullptr, keyType, 
			BCRYPT_RSAFULLPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, exportable, nullptr, 0
		); 
	}
	// проверить идентификатор ключа
	if (dynamic_cast<ANSI::X942::IPrivateKey^>(privateKey) != nullptr) 
	{
		// определить требуемый размер буфера
		DWORD cbBlob = X942::Encoding::GetKeyPairBlob((ANSI::X942::IPublicKey^)publicKey, 
			(ANSI::X942::IPrivateKey^)privateKey, 0, 0
		); 
		// выделить буфер требуемого размера
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DH_KEY_BLOB* pbBlob = (BCRYPT_DH_KEY_BLOB*)&vecBlob[0]; 

		// получить структуру для импорта ключа
		cbBlob = X942::Encoding::GetKeyPairBlob((ANSI::X942::IPublicKey^)publicKey, 
			(ANSI::X942::IPrivateKey^)privateKey, pbBlob, cbBlob
		); 
		// импортировать пару ключей
		return ImportKeyPair(container, hwnd, nullptr, keyType, 
			BCRYPT_DH_PRIVATE_BLOB, IntPtr(pbBlob), cbBlob, true, nullptr, 0
		); 
	}
	// проверить идентификатор ключа
	if (dynamic_cast<ANSI::X957::IPrivateKey^>(privateKey) != nullptr) 
	{
		// определить требуемый размер буфера
		DWORD cbBlob = X957::Encoding::GetKeyPairBlob((ANSI::X957::IPublicKey^)publicKey, 
			(ANSI::X957::IPrivateKey^)privateKey, 0, 0
		); 
		// выделить буфер требуемого размера
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DSA_KEY_BLOB* pbBlob = (BCRYPT_DSA_KEY_BLOB*)&vecBlob[0]; 

		// получить структуру для импорта ключа
		cbBlob = X957::Encoding::GetKeyPairBlob((ANSI::X957::IPublicKey^)publicKey, 
			(ANSI::X957::IPrivateKey^)privateKey, pbBlob, cbBlob
		); 
		// импортировать пару ключей
		return ImportKeyPair(container, hwnd, nullptr, keyType, 
			BCRYPT_DSA_PRIVATE_BLOB, IntPtr(pbBlob), cbBlob, exportable, nullptr, 0
		); 
	}
	// проверить идентификатор ключа
	if (dynamic_cast<ANSI::X962::IPrivateKey^>(privateKey) != nullptr) 
	{
		// преобразовать тип параметров
		ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)publicKey->Parameters; 
		
		// определить имя алгоритма
		String^ algName = X962::Encoding::GetKeyName(parameters, keyType); 

		// определить требуемый размер буфера
		DWORD cbBlob = X962::Encoding::GetKeyPairBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 
			(ANSI::X962::IPrivateKey^)privateKey, 0, 0
		); 
		// выделить буфер требуемого размера
		std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

		// получить структуру для импорта ключа
		cbBlob = X962::Encoding::GetKeyPairBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 
			(ANSI::X962::IPrivateKey^)privateKey, pbBlob, cbBlob
		); 
		// импортировать пару ключей
		return ImportKeyPair(container, hwnd, nullptr, keyType, 
			BCRYPT_ECCPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, exportable, nullptr, 0
		); 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException();
}

Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Provider::CreateGenerator(
	CAPI::Factory^ factory, SecurityObject^ scope, 
	String^ keyOID, IParameters^ parameters, IRand^ rand)
{$
	// проверить тип параметров
	if (keyOID == ASN1::ISO::PKCS::PKCS1::OID::rsa)
	{
		// преобразовать тип параметров
		ANSI::RSA::IParameters^ rsaParameters = (ANSI::RSA::IParameters^)parameters;

		// проверить значение экспоненты
		if (rsaParameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) return nullptr;

		// проверить поддержку алгоритма
		if (algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM) || 
			algs[NCRYPT_SIGNATURE_OPERATION            ]->Contains(NCRYPT_RSA_ALGORITHM))
		{
			// создать алгоритм генерации ключей
			return gcnew RSA::NKeyPairGenerator(this, scope, rand, rsaParameters);
		}
		return nullptr; 
	}
	// проверить тип параметров
	if (keyOID == ASN1::ANSI::OID::x942_dh_public_key) 
	{
		// преобразовать тип параметров
		ANSI::X942::IParameters^ dhParameters = (ANSI::X942::IParameters^)parameters; 

		// проверить поддержку алгоритма
		if (!algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_DH_ALGORITHM)) return nullptr; 

		// создать алгоритм генерации ключей
		return gcnew X942::NKeyPairGenerator(this, scope, rand, dhParameters);
	}
	// проверить тип параметров
	if (keyOID == ASN1::ANSI::OID::x957_dsa) 
	{
		// преобразовать тип параметров
		ANSI::X957::IParameters^ dsaParameters = (ANSI::X957::IParameters^)parameters; 

		// проверить поддержку алгоритма
		if (!algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_DSA_ALGORITHM)) return nullptr; 

		// создать алгоритм генерации ключей
		return gcnew X957::NKeyPairGenerator(this, scope, rand, dsaParameters);
	}
	// проверить тип параметров
	if (keyOID == ASN1::ANSI::OID::x962_ec_public_key) 
	{
		// преобразовать тип параметров
		ANSI::X962::IParameters^ ecParameters = (ANSI::X962::IParameters^)parameters; 

		// проверить поддержку алгоритма
		if (algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P256_ALGORITHM) || 
			algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P384_ALGORITHM) || 
			algs[NCRYPT_SIGNATURE_OPERATION       ]->Contains(NCRYPT_ECDSA_P521_ALGORITHM) || 
			algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P256_ALGORITHM ) || 
			algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P384_ALGORITHM ) || 
			algs[NCRYPT_SECRET_AGREEMENT_OPERATION]->Contains(NCRYPT_ECDH_P521_ALGORITHM ))
		{
			// создать алгоритм генерации ключей
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
	// определить идентификатор алгоритма
	String^ oid = parameters->Algorithm->Value; for (int i = 0; i < 1; i++)
	{
		// для алгоритмов хэширования
		if (type == CAPI::Hash::typeid)
		{
			// создать алгоритм для параметров
			if (IAlgorithm^ algorithm = ((Factory^)primitiveFactory)->
				CreateAlgorithm<CAPI::Hash^>(scope, parameters)) return algorithm; 
		}
		// для алгоритмов вычисления имитовставки
		else if (type == Mac::typeid)
		{
			// создать алгоритм для параметров
			if (IAlgorithm^ algorithm = ((Factory^)primitiveFactory)->
				CreateAlgorithm<Mac^>(scope, parameters)) return algorithm; 
		}
		// для алгоритмов шифрования
		else if (type == CAPI::Cipher::typeid)
		{
			// создать алгоритм для параметров
			if (IAlgorithm^ algorithm = ((Factory^)primitiveFactory)->
				CreateAlgorithm<CAPI::Cipher^>(scope, parameters)) return algorithm; 
		}
		// для алгоритмов асимметричного шифрования
		else if (type == Encipherment::typeid)
		{
			// проверить поддержку алгоритма
			if (algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM))
			{
				// создать алгоритм асимметричного шифрования
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
				{
					// создать алгоритм асимметричного шифрования
					return gcnew Keyx::RSA::PKCS1::NEncipherment(this); 
				}
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) 
				{
					// раскодировать параметры
					ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams^ algParameters = 
						gcnew ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams(parameters->Parameters);

					// получить алгоритм хэширования
					Using<CAPI::Hash^> hashAlgorithm(
						((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
							scope, algParameters->HashAlgorithm
					)); 
					// проверить поддержку алгоритма
					if (hashAlgorithm.Get() == nullptr) break;  

					// получить идентификатор алгоритма хэширования
					String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

					// определить идентификатор маскирования
					String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

					// проверить поддержку параметров
					if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
					
					// раскодировать параметры маскирования
					ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
						gcnew ASN1::ISO::AlgorithmIdentifier(
							algParameters->MaskGenAlgorithm->Parameters
					); 
					// проверить совпадение хэш-алгоритма
					if (maskHashParameters->Algorithm->Value != hashOID) break; 

					// создать алгоритм асимметричного шифрования
					return gcnew Keyx::RSA::OAEP::NEncipherment(
						this, hashOID, algParameters->Label->Value
					);
				}
			}
		}
		// для алгоритмов асимметричного шифрования
		else if (type == Decipherment::typeid)
		{
			// проверить поддержку алгоритма
			if (algs[NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM)) 
			{
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
				{
					// создать алгоритм асимметричного шифрования
					return gcnew Keyx::RSA::PKCS1::NDecipherment(); 
				}
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep) 
				{
					// раскодировать параметры
					ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams^ algParameters = 
						gcnew ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams(parameters->Parameters);

					// получить алгоритм хэширования
					Using<CAPI::Hash^> hashAlgorithm(
						((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
							scope, algParameters->HashAlgorithm
					)); 
					// проверить поддержку алгоритма
					if (hashAlgorithm.Get() == nullptr) break;  

					// получить идентификатор алгоритма хэширования
					String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

					// определить идентификатор маскирования
					String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

					// проверить поддержку параметров
					if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
					
					// раскодировать параметры маскирования
					ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
						gcnew ASN1::ISO::AlgorithmIdentifier(
							algParameters->MaskGenAlgorithm->Parameters
					); 
					// проверить совпадение хэш-алгоритма
					if (maskHashParameters->Algorithm->Value != hashOID) break; 

					// создать алгоритм асимметричного шифрования
					return gcnew Keyx::RSA::OAEP::NDecipherment(
						hashOID, algParameters->Label->Value
					);
				}
			}
		}
		// для алгоритмов подписи
		else if (type == SignHash::typeid)
		{
			// проверить поддержку алгоритма
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM))
			{
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
				{
					// создать алгоритм подписи хэш-значения
					return gcnew Sign::RSA::PKCS1::NSignHash();
				}
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_pss)
				{
					// раскодировать параметры алгоритма
					ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams^ algParameters = 
						gcnew ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams(parameters->Parameters); 
 
					// проверить поддержку параметров
					if (algParameters->TrailerField->Value->IntValue != 0x01) break; 

					// получить алгоритм хэширования
					Using<CAPI::Hash^> hashAlgorithm(
						((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
							scope, algParameters->HashAlgorithm
					)); 
					// проверить поддержку алгоритма
					if (hashAlgorithm.Get() == nullptr) break;  

					// получить идентификатор алгоритма хэширования
					String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

					// определить идентификатор маскирования
					String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

					// проверить поддержку параметров
					if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
					
					// раскодировать параметры маскирования
					ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
						gcnew ASN1::ISO::AlgorithmIdentifier(
							algParameters->MaskGenAlgorithm->Parameters
					); 
					// проверить совпадение хэш-алгоритма
					if (maskHashParameters->Algorithm->Value != hashOID) break; 

					// создать алгоритм подписи данных
					return gcnew Sign::RSA::PSS::NSignHash(
						hashOID, algParameters->SaltLength->IntValue
					);
				}
			}
			// проверить поддержку алгоритма
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_DSA_ALGORITHM))
			{
				// создать алгоритм подписи хэш-значения
				if (oid == ASN1::ANSI::OID::x957_dsa) return gcnew Sign::DSA::NSignHash(); 
			}
			// проверить поддержку алгоритма
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P256_ALGORITHM) || 
				algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P384_ALGORITHM) ||
				algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P521_ALGORITHM))
			{
				// создать алгоритм подписи хэш-значения
				if (oid == ASN1::ANSI::OID::x962_ecdsa_sha1) return gcnew Sign::ECDSA::NSignHash(); 
			}
		}
		// для алгоритмов подписи
		else if (type == VerifyHash::typeid)
		{
			// проверить поддержку алгоритма
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_RSA_ALGORITHM))
			{
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
				{
					// создать алгоритм подписи хэш-значения
					return gcnew Sign::RSA::PKCS1::NVerifyHash(this);
				}
				if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa_pss)
				{
					// раскодировать параметры алгоритма
					ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams^ algParameters = 
						gcnew ASN1::ISO::PKCS::PKCS1::RSASSAPSSParams(parameters->Parameters); 
 
					// проверить поддержку параметров
					if (algParameters->TrailerField->Value->IntValue != 0x01) break; 

					// получить алгоритм хэширования
					Using<CAPI::Hash^> hashAlgorithm(
						((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(
							scope, algParameters->HashAlgorithm
					)); 
					// получить идентификатор алгоритма хэширования
					String^ hashOID = algParameters->HashAlgorithm->Algorithm->Value; 

					// определить идентификатор маскирования
					String^ maskOID = algParameters->MaskGenAlgorithm->Algorithm->Value; 

					// проверить поддержку параметров
					if (maskOID != ASN1::ISO::PKCS::PKCS1::OID::rsa_mgf1) break; 
					
					// раскодировать параметры маскирования
					ASN1::ISO::AlgorithmIdentifier^ maskHashParameters = 
						gcnew ASN1::ISO::AlgorithmIdentifier(
							algParameters->MaskGenAlgorithm->Parameters
					); 
					// проверить совпадение хэш-алгоритма
					if (maskHashParameters->Algorithm->Value != hashOID) break; 

					// создать алгоритм подписи данных
					return gcnew Sign::RSA::PSS::NVerifyHash(
						this, hashOID, algParameters->SaltLength->IntValue
					);
				}
			}
			// проверить поддержку алгоритма
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_DSA_ALGORITHM))
			{
				// создать алгоритм подписи хэш-значения
				if (oid == ASN1::ANSI::OID::x957_dsa) return gcnew Sign::DSA::NVerifyHash(this); 
			}
			// проверить поддержку алгоритма
			if (algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P256_ALGORITHM) || 
				algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P384_ALGORITHM) ||
				algs[NCRYPT_SIGNATURE_OPERATION]->Contains(NCRYPT_ECDSA_P521_ALGORITHM))
			{
				// создать алгоритм подписи хэш-значения
				if (oid == ASN1::ANSI::OID::x962_ecdsa_sha1) return gcnew Sign::ECDSA::NVerifyHash(this); 
			}
		}
		// для алгоритмов подписи
		else if (type == SignData::typeid)
		{
			// подпись DSA поддерживается только для SHA1
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_224) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_256) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_512) return nullptr; 
		}
		// для алгоритмов проверки подписи
		else if (type == VerifyData::typeid)
		{
			// подпись DSA поддерживается только для SHA1
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_224) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_256) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_384) return nullptr; 
	        if (oid == ASN1::ANSI::OID::nist_dsa_sha2_512) return nullptr; 
		}
		// для алгоритмов согласования общего ключа
		else if (type == ITransportAgreement::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS9::OID::smime_ssdh || 
				oid == ASN1::ISO::PKCS::PKCS9::OID::smime_esdh)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
   				// создать алгоритм согласования общего ключа
				return gcnew Keyx::DH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters->Algorithm->Value
				); 
			}
			if (oid == ASN1::ISO::PKCS::PKCS9::OID::smime_esdh)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм согласования общего ключа
				return gcnew Keyx::DH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters->Algorithm->Value
				); 
			}
			if (oid == ASN1::ANSI::OID::x963_ecdh_std_sha1)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::ECDH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
			if (oid == ASN1::ANSI::OID::certicom_ecdh_std_sha2_256)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_256), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::ECDH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
			if (oid == ASN1::ANSI::OID::certicom_ecdh_std_sha2_384)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_384), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::ECDH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
			if (oid == ASN1::ANSI::OID::certicom_ecdh_std_sha2_512)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters->Parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::nist_sha2_512), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					((Factory^)this)->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// создать алгоритм наследования общего ключа
				return gcnew Keyx::ECDH::NKeyAgreement(
					(CAPI::CNG::Hash^)hashAlgorithm.Get(), wrapParameters
				); 
			}
		}
	}
	// вызвать базовую функцию
	return ANSI::Factory::RedirectAlgorithm(factory, scope, parameters, type); 
}
