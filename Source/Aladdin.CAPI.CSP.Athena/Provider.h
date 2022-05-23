#pragma once
#include "SCardStores.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Athena 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Athena
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : Microsoft::RSA::AESEnhancedProvider
	{
		// конструктор
		public: Provider() : Microsoft::RSA::AESEnhancedProvider(
			PROV_RSA_FULL, "Athena ASECard Crypto CSP", false, true) {}

		// имя провайдера
		public: virtual property String^ Name 
		{ 
			// имя провайдера
			String^ get() override { return CAPI::CSP::Provider::Name; }
		}
		// перечислить хранилища контейнера
		public: virtual array<String^>^ EnumerateStores(Scope scope) override
		{
			// создать список имен
			return gcnew array<String^> { "Card" }; 
		}
		// получить хранилище контейнера
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// проверить имя хранилища
			if (name != "Card") throw gcnew NotFoundException(); 

			// вернуть хранилище контейнеров
			return gcnew SCardStores(this, scope); 
		}
		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	};
}}}}
