#pragma once
#include "SCardStores.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace AKS 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер eToken Base
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : Microsoft::RSA::AESEnhancedProvider
	{
		// конструктор
		public: Provider() : Microsoft::RSA::AESEnhancedProvider(
			PROV_RSA_FULL, "eToken Base Cryptographic Provider", false, false) {}

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
		// получить фабрику генераторов случайных данных
		public:	virtual IRandFactory^ CreateRandFactory(SecurityObject^ scope, bool strong) override
		{
			// указать фабрику генераторов
			return RefObject::AddRef(this); 
		}
	};
}}}}