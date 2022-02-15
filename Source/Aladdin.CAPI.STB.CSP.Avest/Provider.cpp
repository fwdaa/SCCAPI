#include "stdafx.h"
#include "Provider.h"
#include "BelT.h"
#include "GOST28147.h"
#include "STB11761.h"
#include "STB11762.h"

using namespace System::Runtime::InteropServices; 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер Авест
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle Aladdin::CAPI::STB::Avest::CSP::Provider::ConstructKey(
	Aladdin::CAPI::CSP::ContextHandle hContext, ALG_ID algID, IKey^ key)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::Provider::ConstructKey); 

	// проверить тип ключа
	if (dynamic_cast<CAPI::CSP::SessionKey^>(key) != nullptr || key->Value == nullptr)
	{
        // вызвать базовую функцию
        return CAPI::CSP::Provider::ConstructKey(hContext, algID, key); 
    }
    else {
	    // проверить размер ключа
	    if (key->Value->Length != 32) throw gcnew CryptographicException(NTE_BAD_LEN); 

	    // задать фиксированный заголовок
	    BLOBHEADER blobHeader = { SIMPLEBLOB, CUR_BLOB_VERSION, 0, algID } ; 

	    // задать структуру импорта ключа шифрования
	    AVEST_SIMPLE_BLOB blob = { blobHeader, 0 }; DWORD cbBlob = sizeof(blob); 
	
	    // скопировать содержимое ключа
	    Marshal::Copy(key->Value, 0, IntPtr(&blob.key), key->Value->Length); 

	    // импортировать ключ в контекст
	    return hContext.ImportKey(CAPI::CSP::KeyHandle::Zero, IntPtr(&blob), cbBlob, CRYPT_EXPORTABLE); 
    }
}

Dictionary<String^, Aladdin::CAPI::KeyUsage>^ 
Aladdin::CAPI::STB::Avest::CSP::Provider::SupportedKeys()		
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::Provider::SupportedKeys); 

    // создать пустой список ключей
    Dictionary<String^, KeyUsage>^ keys = gcnew Dictionary<String^, KeyUsage>(); 

    // добавить поддерживаемый ключ
    keys->Add(KeyOID, KeyUsage::dataSignature | KeyUsage::keyEncipherment); return keys; 
} 

Aladdin::CAPI::IPrivateKey^ 
Aladdin::CAPI::STB::Avest::CSP::Provider::GetPrivateKey(
	IKeyFactory^ keyFactory, CAPI::CSP::Container^ container, 
	CAPI::CSP::KeyHandle hKeyPair, DWORD keyType)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::Provider::GetPrivateKey);

	// проверить идентификатор параметров
	if (keyFactory->Oid == ASN1::STB::Avest::OID::bds_bdh) 
    {
		// при указании контейнера
		if (container != nullptr)
		{
			// создать постоянный личный ключ
			return gcnew STB11762::PrivateKey(container, keyFactory, hKeyPair, keyType); 
		}
		// создать временный личный ключ
		return gcnew STB11762::PrivateKey(this, keyFactory, hKeyPair, keyType); 
    }
	// вызвать базовую функцию
	return CAPI::CSP::Provider::GetPrivateKey(keyFactory, container, hKeyPair, keyType); 
}

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер Авест Full
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IKeyPairGenerator^ Aladdin::CAPI::STB::Avest::CSP::ProviderFull::CreateGenerator(
	IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::ProviderFull::CreateGenerator); 

	// проверить идентификатор параметров
	if (keyFactory->Oid == ASN1::STB::Avest::OID::bds_bdh) 
	{
		// создать алгоритм генерации ключей
		return gcnew STB11762::KeyPairGenerator(this, keyFactory);
	}
	return nullptr; 
}

Aladdin::CAPI::IAlgorithm^ Aladdin::CAPI::STB::Avest::CSP::ProviderFull::CreateAlgorithm(
	ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) 
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::ProviderFull::CreateAlgorithm); 

	// определить идентификатор алгоритма
	String^ oid = parameters->Algorithm->Value; 

	// для алгоритмов хэширования
	if (type == IHash::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::belt_hash) return gcnew BelT::Hash(this, Handle.Context);
		if (oid == ASN1::STB::Avest::OID::bhf      ) 
		{
			// указать стартовое значение
			array<BYTE>^ start = gcnew array<BYTE>(32); for (int i = 0; i < 32; i++) start[i] = 0xAA; 

			// создать алгоритм хэширования
			return gcnew STB11761::Hash(this, Handle.Context, start);
		}
	}
	// для алгоритмов вычисления имитовставки
	else if (type == IMac::typeid)
	{
		// создать алгоритм вычисления имитовставки
		if (oid == ASN1::STB::Avest::OID::gost) 
		{
			// раскодировать параметры
			ASN1::ObjectIdentifier^ sboxOID = gcnew ASN1::ObjectIdentifier(parameters->Parameters); 
			
			// создать алгоритм вычисления имитовставки
			return gcnew GOST28147::Imito(this, Handle.Context, sboxOID->Value); 
		}
	}
	// для алгоритмов симметричного шифрования
	else if (type == ICipher::typeid)
	{
		// создать алгоритм симметричного шифрования
		if (oid == ASN1::STB::Avest::OID::gost_modes_cfb)
		{ 
			// раскодировать параметры
			ASN1::STB::Avest::CipherParameters^ algParameters = 
				gcnew ASN1::STB::Avest::CipherParameters(parameters->Parameters); 

			// создать алгоритм симметричного шифрования
			return gcnew GOST28147::BlockCipher(this, Handle.Context, 
				algParameters->ParamSet->Value, CipherMode::CFB, 
				PaddingMode::None, algParameters->IV->Value
			);
		}
		// создать алгоритм симметричного шифрования
		if (oid == ASN1::STB::Avest::OID::gost_modes_cfb_pad)
		{ 
			// раскодировать параметры
			ASN1::STB::Avest::CipherParameters^ algParameters = 
				gcnew ASN1::STB::Avest::CipherParameters(parameters->Parameters); 

			// создать алгоритм симметричного шифрования
			return gcnew GOST28147::BlockCipher(this, Handle.Context, 
				algParameters->ParamSet->Value, CipherMode::CFB, 
				PaddingMode::PKCS7, algParameters->IV->Value
			);
		}
	}
	// для алгоритмов подписи данных
	else if (type == ISignData::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bds_bhf)
		{
			// создать алгоритм подписи данных
			return gcnew STB11762::SignDataSTB11761(this);
		}
	}
	// для алгоритмов подписи данных
	else if (type == IVerifyData::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bds_bhf)
		{
			// создать алгоритм подписи данных
			return gcnew STB11762::VerifyDataSTB11761(this);
		}
	}
	// для алгоритмов согласования общего ключа
	else if (type == IASN1KeyWrap::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdh) 
		{
			// создать алгоритм согласования общего ключа
			return gcnew STB11762::ASN1KeyWrap(this);
		}
	}
	// для алгоритмов согласования общего ключа
	else if (type == IASN1KeyUnwrap::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdh) 
		{
			// создать алгоритм согласования общего ключа
			return gcnew STB11762::ASN1KeyUnwrap(this);
		}
	}
	return nullptr; 
}

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер Авест Pro
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IKeyPairGenerator^ Aladdin::CAPI::STB::Avest::CSP::ProviderPro::CreateGenerator(
	IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::ProviderPro::CreateGenerator); 

	// проверить идентификатор параметров
	if (keyFactory->Oid == ASN1::STB::Avest::OID::bdspro_bdh) 
	{
		// создать алгоритм генерации ключей
		return gcnew STB11762::KeyPairGenerator(this, keyFactory);
	}
	return nullptr; 
}

Aladdin::CAPI::IAlgorithm^ Aladdin::CAPI::STB::Avest::CSP::ProviderPro::CreateAlgorithm(
	ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) 
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::ProviderPro::CreateAlgorithm); 

	// определить идентификатор алгоритма
	String^ oid = parameters->Algorithm->Value; 

	// для алгоритмов хэширования
	if (type == IHash::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::belt_hash) return gcnew BelT::Hash(this, Handle.Context);
		if (oid == ASN1::STB::Avest::OID::bhf      ) 
		{
			// указать стартовое значение
			array<BYTE>^ start = gcnew array<BYTE>(32); for (int i = 0; i < 32; i++) start[i] = 0xAA; 

			// создать алгоритм хэширования
			return gcnew STB11761::Hash(this, Handle.Context, start);
		}
	}
	// для алгоритмов вычисления имитовставки
	else if (type == IMac::typeid)
	{
		// создать алгоритм вычисления имитовставки
		if (oid == ASN1::STB::Avest::OID::gost) 
		{
			// раскодировать параметры
			ASN1::ObjectIdentifier^ sboxOID = gcnew ASN1::ObjectIdentifier(parameters->Parameters); 
			
			// создать алгоритм вычисления имитовставки
			return gcnew GOST28147::Imito(this, Handle.Context, sboxOID->Value); 
		}
	}
	// для алгоритмов симметричного шифрования
	else if (type == ICipher::typeid)
	{
		// создать алгоритм симметричного шифрования
		if (oid == ASN1::STB::Avest::OID::gost_modes_cfb)
		{ 
			// раскодировать параметры
			ASN1::STB::Avest::CipherParameters^ algParameters = 
				gcnew ASN1::STB::Avest::CipherParameters(parameters->Parameters); 

			// создать алгоритм симметричного шифрования
			return gcnew GOST28147::BlockCipher(this, Handle.Context, 
				algParameters->ParamSet->Value, CipherMode::CFB, 
				PaddingMode::None, algParameters->IV->Value
			);
		}
		// создать алгоритм симметричного шифрования
		if (oid == ASN1::STB::Avest::OID::gost_modes_cfb_pad)
		{ 
			// раскодировать параметры
			ASN1::STB::Avest::CipherParameters^ algParameters = 
				gcnew ASN1::STB::Avest::CipherParameters(parameters->Parameters); 

			// создать алгоритм симметричного шифрования
			return gcnew GOST28147::BlockCipher(this, Handle.Context, 
				algParameters->ParamSet->Value, CipherMode::CFB, 
				PaddingMode::PKCS7, algParameters->IV->Value
			);
		}
	}
	// для алгоритмов подписи хэш-значения
	else if (type == ISignHash::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bds) 
		{
			// создать алгоритм подписи хэш-значения
			return gcnew STB11762::SignHash(this);
		}
		if (oid == ASN1::STB::Avest::OID::bdspro) 
		{
			// создать алгоритм подписи хэш-значения
			return gcnew STB11762::SignHash(this);
		}
	}
	// для алгоритмов подписи хэш-значения
	else if (type == IVerifyHash::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bds) 
		{
			// создать алгоритм подписи хэш-значения
			return gcnew STB11762::VerifyHash(this);
		}
		if (oid == ASN1::STB::Avest::OID::bdspro) 
		{
			// создать алгоритм подписи хэш-значения
			return gcnew STB11762::VerifyHash(this);
		}
	}
	// для алгоритмов подписи данных
	else if (type == ISignData::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdspro_bhf) 
		{
			// создать алгоритм подписи данных
			return gcnew STB11762::SignDataSTB11761(this);
		}
		if (oid == ASN1::STB::Avest::OID::bdspro_belt) 
		{
			// создать алгоритм подписи данных
			return gcnew STB11762::SignDataBelT(this);
		}
	}
	// для алгоритмов подписи данных
	else if (type == IVerifyData::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdspro_bhf) 
		{
			// создать алгоритм подписи данных
			return gcnew STB11762::VerifyDataSTB11761(this);
		}
		if (oid == ASN1::STB::Avest::OID::bdspro_belt) 
		{
			// создать алгоритм подписи данных
			return gcnew STB11762::VerifyDataBelT(this);
		}
	}
	// для алгоритмов согласования общего ключа
	else if (type == IASN1KeyWrap::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdh) 
		{
			// создать алгоритм согласования общего ключа
			return gcnew STB11762::ASN1KeyWrap(this);
		}
	}
	// для алгоритмов согласования общего ключа
	else if (type == IASN1KeyUnwrap::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdh) 
		{
			// создать алгоритм согласования общего ключа
			return gcnew STB11762::ASN1KeyUnwrap(this);
		}
	}
	return nullptr; 
}
