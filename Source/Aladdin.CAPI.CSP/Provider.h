#pragma once
#include "Handle.h"
#include "Key.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	ref class Container; 

	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CryptoProvider
	{
		private: Using<ProviderHandle^> handle;    // описатель провайдера
		private: Using<ProviderHandle^> handleGUI; // описатель провайдера
        private: DWORD		            type;      // тип провайдера

		// фабрики кодирования ключей 
		private: Dictionary<String^, SecretKeyFactory^>^ secretKeyFactories; 
		private: Dictionary<String^,       KeyFactory^>^       keyFactories; 

		// конструктор
		protected: Provider(DWORD type, String^ szName, bool sspi); 
		// деструктор
		public: virtual ~Provider();  

		// тип провайдера
		public: virtual property DWORD Type { DWORD get() { return type; }}
        // имя провайдера
        public:	virtual property String^ Name { String^ get() override { return handle.Get()->Name; }}

		// описатель провайдера
		public: property ProviderHandle^ Handle { ProviderHandle^ get() { return handle.Get(); }}

        // номер версии провайдера
        public: property DWORD Version { DWORD get() { return handle.Get()->GetLong(PP_VERSION, 0); }}

		// поддерживаемые фабрики кодирования ключей
		public: virtual Dictionary<String^, SecretKeyFactory^>^ SecretKeyFactories() override { return secretKeyFactories; }
		public: virtual Dictionary<String^,       KeyFactory^>^       KeyFactories() override { return       keyFactories; }

		///////////////////////////////////////////////////////////////////////
		// Генерация случайных данных
		///////////////////////////////////////////////////////////////////////

		// получить фабрику генераторов случайных данных
		public:	virtual IRandFactory^ CreateRandFactory(SecurityObject^ scope, bool strong) override; 
		// получить генератор случайных данных
		public:	virtual IRand^ CreateRand(Object^ window) override; 

		///////////////////////////////////////////////////////////////////////
		// Выполнение операции с симметричным ключом
		///////////////////////////////////////////////////////////////////////

		// получить тип ключа
		public: virtual SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) = 0; 

	    // импортировать ключ
		public protected: virtual KeyHandle^ ImportKey(
			Container^ container, KeyHandle^ hPrivateKey, 
			IntPtr pBlob, DWORD cbBlob, DWORD flags
		); 
		///////////////////////////////////////////////////////////////////////
		// Выполнение операции с открытым/личным ключом контейнера
		///////////////////////////////////////////////////////////////////////

		// преобразовать идентификатор ключа
		public: virtual String^ ConvertKeyOID(ALG_ID algID) = 0; 

		// преобразовать идентификатор ключа
		public: virtual ALG_ID ConvertKeyOID(String^ keyOID, DWORD keyType) = 0; 

		// импортировать пару ключей
		public protected: virtual KeyHandle^ ImportKeyPair(
			Container^ container, DWORD keyType, DWORD keyFlags, 
			IPublicKey^ publicKey, IPrivateKey^ privateKey
		); 
		// импортировать открытый ключ
		public protected: virtual KeyHandle^ ImportPublicKey(
			ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType
        );
 		// экспортировать открытый ключ
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
			ExportPublicKey(KeyHandle^ hPublicKey);

		// получить личный ключ
		public protected: virtual PrivateKey^ GetPrivateKey(SecurityObject^ scope, 
            IPublicKey^ publicKey, KeyHandle^ hKeyPair, DWORD keyType
		); 
	};
}}}