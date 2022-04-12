#pragma once
#include "SCardStores.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Tumar CSP
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : ANSI::CSP::Microsoft::RSA::AESEnhancedProvider
	{
		// конструктор
		protected: Provider(DWORD type, String^ name, bool sspi) 
			
			// сохранить переданные параметры
			: ANSI::CSP::Microsoft::RSA::AESEnhancedProvider(type, name, sspi, false) 
		{
			// указать фабрику алгоритмов
			Using<CAPI::Factory^> factory(gcnew KZ::Factory()); 

			// для всех фабрик алгоритмов
			for each (KeyValuePair<String^, CAPI::KeyFactory^> item in factory.Get()->KeyFactories())
			{
				// добавить фабрики алгоритмов
				KeyFactories()->Add(item.Key, item.Value); 
			}
		}
		// имя группы провайдеров
		public: virtual property String^ Group { String^ get() override { return GT_TUMAR_PROV; }}

		// имя провайдера
		public: virtual property String^ Name 
		{ 
			// имя провайдера
			String^ get() override { return CAPI::CSP::Provider::Name; }
		}
		// получить хранилище контейнера
		public: virtual array<String^>^ EnumerateStores(Scope scope) override 
		{ 
			// вернуть список хранилищ
			return gcnew array<String^> { "Card" }; 
		}
		// получить хранилище контейнера
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// вернуть хранилище контейнеров
			return gcnew SCardStores(this, scope); 
		}
		// создать алгоритм генерации ключей
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			CAPI::Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;

		// получить тип ключа
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override; 

		///////////////////////////////////////////////////////////////////////
		// Выполнение операции с открытым/личным ключом контейнера
		///////////////////////////////////////////////////////////////////////

		// преобразовать идентификатор ключа
		public: virtual String^ ConvertKeyOID(ALG_ID keyID) override; 

		// преобразовать идентификатор ключа
		public: virtual ALG_ID ConvertKeyOID(String^ keyID, DWORD keyType) override; 

		// импортировать открытый ключ
		public: virtual CAPI::CSP::KeyHandle^ ImportPublicKey(
			CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType) override;
 
		// экспортировать открытый ключ
		public: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
			ExportPublicKey(CAPI::CSP::KeyHandle^ hPublicKey) override;

		// импортировать пару ключей
		public protected: virtual CAPI::CSP::KeyHandle^ ImportKeyPair(
			CAPI::CSP::Container^ container, DWORD keyType, 
			DWORD keyFlags, IPublicKey^ publicKey, IPrivateKey^ privateKey) override; 

		// получить личный ключ
		public protected: virtual CAPI::CSP::PrivateKey^ GetPrivateKey(
			SecurityObject^ scope, IPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType) override; 
	};
}}}}}
