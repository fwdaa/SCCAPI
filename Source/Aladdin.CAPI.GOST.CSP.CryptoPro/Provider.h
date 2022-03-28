#pragma once
#include "RegistryStore.h"
#include "SCardStores.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер КриптоПро
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CSP::Provider
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian;
		   
		// конструктор
		public: Provider(DWORD type) : CAPI::CSP::Provider(type, nullptr, false)
		
			// сохранить версию провайдера
			{ version = Version; } private: DWORD version;

        // время сборки провайдера
        public: property String^ Timestamp { String^ get()
        {
            // получить время сборки провайдера
            return Handle->GetString(PP_VERSION_TIMESTAMP, 0);
        }}
		// имя группы провайдеров
		public: virtual property String^ Group { String^ get() override 
		{ 
			// имя группы провайдеров
			return CP_GR3410_2001_PROV_W; 
		}}
		// получить хранилище контейнера
		public: virtual array<String^>^ EnumerateStores(Scope scope) override 
		{ 
			// вернуть имена хранилищ контейнеров
			if (scope == Scope::System) return gcnew array<String^> { "HKLM", "Card" }; 
			if (scope == Scope::User  ) return gcnew array<String^> { "HKCU", "Card" }; 

			return gcnew array<String^>(0); 
		}
		// перечислить все контейнеры
		public: virtual array<SecurityInfo^>^ EnumerateAllObjects(Scope scope) override; 

		// получить хранилище контейнеров
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ storeName) override 
		{ 
			if (scope == Scope::System) 
			{
				// вернуть хранилище контейнеров
				if (storeName == "HKLM") return RegistryStore::Create(this, scope); 
				if (storeName == "Card") return gcnew SCardStores    (this, scope); 
			}
			if (scope == Scope::User) 
			{
				// вернуть хранилище контейнеров
				if (storeName == "HKCU") return RegistryStore::Create(this, scope); 
				if (storeName == "Card") return gcnew SCardStores    (this, scope); 
			}
			// при ошибке выбросить исключение
			throw gcnew NotFoundException(); 
		}
		// создать алгоритм шифрования ГОСТ 28147-89
		public: CAPI::CSP::BlockCipher^ CreateGOST28147(String^ paramOID); 

	    // поддерживаемые фабрики кодирования ключей
		public: virtual array<KeyFactory^>^ KeyFactories() override; 

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			CAPI::Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;

		// получить тип ключа
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override; 

		///////////////////////////////////////////////////////////////////////
		// Выполнение операции с открытым/личным ключом контейнера
		///////////////////////////////////////////////////////////////////////

        // идентификатор алгоритма шифрования ключа
        public protected: String^ GetExportKeyOID(String^ keyOID, DWORD keyType); 

        // идентификатор алгоритма шифрования ключа
        public protected: ALG_ID GetExportID(String^ keyOID)
        {
            // вернуть идентификатор алгоритма шифрования ключа 
            return (keyOID == ASN1::GOST::OID::gostR3410_2001) ? CALG_PRO_EXPORT : CALG_PRO12_EXPORT; 
        } 
	    // создать алгоритм шифрования ключа
		public protected: KeyWrap^ CreateExportKeyWrap(
			CAPI::CSP::ContextHandle^ hContext, 
			ALG_ID exportID, String^ sboxOID, array<BYTE>^ ukm
		);
		// преобразовать идентификатор ключа
		public: virtual String^ ConvertKeyOID(ALG_ID keyOID) override; 

		// преобразовать идентификатор ключа
		public: virtual ALG_ID ConvertKeyOID(String^ keyOID, DWORD keyType) override; 

		// импортировать пару ключей
		public protected: virtual Aladdin::CAPI::CSP::KeyHandle^ ImportKeyPair(
			CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
			IPublicKey^ publicKey, IPrivateKey^ privateKey) override; 

		// импортировать открытый ключ
		public protected: virtual CAPI::CSP::KeyHandle^ ImportPublicKey(
			CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType) override; 

		// преобразовать формат открытого ключа
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ ExportPublicKey(
			CAPI::CSP::KeyHandle^ hPublicKey) override;
		
		// получить личный ключ
		public protected: virtual CAPI::CSP::PrivateKey^ GetPrivateKey(SecurityObject^ scope, 
			IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType
		) override;
	}; 
}}}}}
