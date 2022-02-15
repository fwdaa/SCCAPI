#pragma once
#include "..\Provider.h"
#include "..\RegistryStore.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace DSS 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер DSS
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : Microsoft::Provider
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// конструктор
		public: Provider(DWORD type, String^ name, bool sspi) : Microsoft::Provider(type, name, sspi) {}

		// поддерживаемые фабрики кодирования ключей
		public: virtual array<SecretKeyFactory^>^ SecretKeyFactories() override
		{
			// поддерживаемые фабрики кодирования ключей
			return gcnew array<SecretKeyFactory^> { 
				ANSI::Keys::RC2 ::Instance, ANSI::Keys::RC4 ::Instance, 
				ANSI::Keys::DES ::Instance, ANSI::Keys::DESX::Instance, 
				ANSI::Keys::TDES::Instance
			}; 
		}
		// вернуть тип ключа
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override;

		// поддерживаемые фабрики кодирования ключей
		public: virtual array<KeyFactory^>^ KeyFactories() override
		{
			// поддерживаемые фабрики кодирования ключей
			return gcnew array<KeyFactory^> { 
				gcnew ANSI::X942::KeyFactory(ASN1::ANSI::OID::x942_dh_public_key), 
				gcnew ANSI::X957::KeyFactory(ASN1::ANSI::OID::x957_dsa          )
			}; 
		}
		// перечислить хранилища контейнеров
		public: virtual array<String^>^ EnumerateStores(Scope scope) override
		{
			// указать имена хранилищ
			if (scope == Scope::System) return gcnew array<String^> { "HKLM" }; 
			if (scope == Scope::User  ) return gcnew array<String^> { "HKCU" }; 

			return gcnew array<String^>(0); 
		}
		// получить хранилище контейнера
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override
		{
			// проверить совпадение имени
			if (scope == Scope::System && name != "HKLM")
			{
				// при ошибке выбросить исключение
				throw gcnew NotFoundException(); 
			}
			// проверить совпадение имени
			if (scope == Scope::User && name != "HKCU")
			{
				// при ошибке выбросить исключение
				throw gcnew NotFoundException(); 
			}
			// вернуть хранилище контейнеров
			return gcnew RegistryStore(this, scope);
		}
		// создать алгоритм генерации ключей
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			Factory^ outer, SecurityObject^ scope, 
			String^ keyOID, IParameters^ parameters, IRand^ rand) override; 

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;

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

		// преобразовать идентификатор ключа
		public: virtual String^ ConvertKeyOID(ALG_ID algID) override
		{
			switch (algID)
			{
			// вернуть идентификатор ключа
			case CALG_DSS_SIGN	: return ASN1::ANSI::OID::x957_dsa;
			case CALG_DH_SF		: return ASN1::ANSI::OID::x942_dh_public_key;
			case CALG_DH_EPHEM	: return ASN1::ANSI::OID::x942_dh_public_key;
			}
			// неподдерживаемый ключ
			throw gcnew NotSupportedException(); 
		}
		// преобразовать идентификатор ключа
		public: virtual ALG_ID ConvertKeyOID(String^ keyOID, DWORD keyType) override
		{
			if (keyOID == ASN1::ANSI::OID::x942_dh_public_key)
			{
				// вернуть идентификатор ключа
				if (keyType == AT_KEYEXCHANGE) return CALG_DH_SF; 
			}
			if (keyOID == ASN1::ANSI::OID::x957_dsa)
			{
				// вернуть идентификатор ключа
				if (keyType == AT_SIGNATURE) return CALG_DSS_SIGN; 
			}
			// неподдерживаемый ключ
			throw gcnew NotSupportedException(); 
		}
	};
}}}}}}
