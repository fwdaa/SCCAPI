#pragma once

#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// Фабрика создания алгоритмов
	///////////////////////////////////////////////////////////////////////////
	public ref class Factory : CAPI::Factory
	{
		// криптографические провайдеры
		private: Dictionary<String^, CAPI::Provider^>^ providers;  
	
		// конструктор
		public: Factory()
		{
			// создать список провайдеров
			providers = gcnew Dictionary<String^, CAPI::Provider^>();
			
			// создать провайдеры
			Provider^ providerFull = gcnew ProviderFull(this); 
			Provider^ providerPro  = gcnew ProviderPro (this); 

			// добавить провайдер в список
			providers->Add(providerFull->Name, providerFull);
			providers->Add(providerPro ->Name, providerPro );
		}
		// вернуть поддерживаемые провайдеры
		public: virtual property Dictionary<String^, CAPI::Provider^>^ Providers 
		{ 
			// вернуть поддерживаемые провайдеры
			Dictionary<String^, CAPI::Provider^>^ get() override { return providers; } 
		} 
		// вернуть фабрику ключей
		public: virtual IKeyFactory^ GetKeyFactory(
			ASN1::ISO::AlgorithmIdentifier^ parameters) override; 

		// создать алгоритм генерации ключей
		public: virtual IKeyPairGenerator^ CreateGenerator(
			IKeyFactory^ keyFactory, IRand^ rand) override; 

		// создать алгоритм для параметров
		public: virtual IAlgorithm^ CreateAlgorithm(
			ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) override;
	};
}}}}}