#pragma once
#include "..\Provider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер RSA
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : Microsoft::Provider
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; private: bool oaep; 

		// фабрики кодирования ключей 
		private: Dictionary<String^, SecretKeyFactory^>^ secretKeyFactories; 
		private: Dictionary<String^,       KeyFactory^>^       keyFactories; 

		// конструктор
		public: Provider(DWORD type, String^ name, bool sspi, bool oaep) 

			// сохранить переданные параметры
			: Microsoft::Provider(type, name, sspi) { this->oaep = oaep; 

			// заполнить список фабрик кодирования ключей
			KeyFactories()->Add(ASN1::ISO::PKCS::PKCS1::OID::rsa, 
				gcnew ANSI::RSA::KeyFactory(ASN1::ISO::PKCS::PKCS1::OID::rsa)
			); 
			if (oaep) KeyFactories()->Add(ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep, 
				gcnew ANSI::RSA::KeyFactory(ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep)
			); 
		} 

		// вернуть тип ключа
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override;

		// создать алгоритм генерации ключей
		public protected: virtual CAPI::KeyPairGenerator^ CreateGenerator(
			Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;

		// импортировать пару ключей
		public protected: virtual CAPI::CSP::KeyHandle^ ImportKeyPair(
			CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
			IPublicKey^ publicKey, IPrivateKey^ privateKey) override;

		// импортировать открытый ключ
		public protected: virtual CAPI::CSP::KeyHandle^ ImportPublicKey(
			CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType) override; 

		// экспортировать открытый ключ
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ ExportPublicKey(
			CAPI::CSP::KeyHandle^ hPublicKey) override; 

		// получить личный ключ
		public protected: virtual CAPI::CSP::PrivateKey^ GetPrivateKey(SecurityObject^ scope, 
			IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType
		) override;

		// получить идентификатор ключа
		public: virtual String^ ConvertKeyOID(ALG_ID algID) override
		{
			switch (algID)
			{
			// вернуть идентификатор ключа
			case CALG_RSA_KEYX: return ASN1::ISO::PKCS::PKCS1::OID::rsa; 
			case CALG_RSA_SIGN: return ASN1::ISO::PKCS::PKCS1::OID::rsa; 
			}
			// неподдерживаемый ключ
			throw gcnew NotSupportedException(); 
		}
		// преобразовать идентификатор ключа
		public: virtual ALG_ID ConvertKeyOID(String^ keyOID, DWORD keyType) override
		{
			if (keyOID == ASN1::ISO::PKCS::PKCS1::OID::rsa)
			{
				// вернуть идентификатор ключа
				return (keyType == AT_KEYEXCHANGE) ? CALG_RSA_KEYX : CALG_RSA_SIGN; 
			}
			// неподдерживаемый ключ
			throw gcnew NotSupportedException(); 
		}
	}; 
}}}}}}
