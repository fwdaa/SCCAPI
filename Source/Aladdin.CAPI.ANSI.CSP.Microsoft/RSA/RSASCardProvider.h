#pragma once
#include "AESEnhancedProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Base Smart Card
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardProvider : AESEnhancedProvider
	{
		// конструктор
		public: SCardProvider() : AESEnhancedProvider(PROV_RSA_FULL, MS_SCARD_PROV_W, false, false) {}

		// имя группы
		public: virtual property String^ Group { String^ get() override { return Name; }}
		// имя провайдера
		public: virtual property String^ Name { String^ get() override { return Provider::Name; }}

		// перечислить хранилища контейнера
		public: virtual array<String^>^ EnumerateStores(Scope scope) override
		{
			// создать список имен
			return gcnew array<String^> { "Card" }; 
		}
		// получить хранилище контейнера
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// вернуть хранилище контейнеров
			return gcnew CAPI::CSP::SCardStores(this, scope, 0); 
		}
		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;
	};
}}}}}}
