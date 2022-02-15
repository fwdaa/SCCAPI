#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	//////////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	//////////////////////////////////////////////////////////////////////////////
	public ref class BKeyPairGenerator abstract : Software::KeyPairGenerator
    {
		// фабрика алгоритмов и криптографический контекст
		private: Using<BProviderHandle^> hProvider;

		// конструктор
		protected: BKeyPairGenerator(CAPI::Factory^ factory, SecurityObject^ scope, 
			IRand^ rand, String^ provider, String^ alg, DWORD flags) 
			
			// сохранить переданные параметры
			: Software::KeyPairGenerator(factory, scope, rand), 

				// открыть провайддер алгоритма
				hProvider(gcnew BProviderHandle(provider, alg, flags)) {}

		// описатель криптографического контекста
		protected: property BProviderHandle^ Handle 
		{ 
			// описатель криптографического контекста
			BProviderHandle^ get() { return hProvider.Get(); }
		}
	};
	//////////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	//////////////////////////////////////////////////////////////////////////////
    public ref class NKeyPairGenerator abstract : KeyPairGenerator
    {
		// параметры ключей
		private: IParameters^ parameters; 

		// конструктор
		protected: NKeyPairGenerator(NProvider^ provider, 
			SecurityObject^ scope, IRand^ rand, IParameters^ parameters)
			
			// сохранить переданные параметры
			: KeyPairGenerator(provider, scope, rand) { this->parameters = parameters; }

        // криптографический провайдер
		public: property NProvider^	Provider 
		{ 
			// криптографический провайдер
			NProvider^ get() { return (NProvider^)Factory; }
		}
		// параметры ключей
		public: property IParameters^ Parameters { IParameters^	get() { return parameters; }}

		// сгенерировать пару ключей
		public: virtual KeyPair^ Generate(array<BYTE>^ keyID, 
			String^ keyOID, KeyUsage keyUsage, KeyFlags keyFlags) override; 

		// сгенерировать пару ключей
		public: virtual KeyPair^ Generate(String^ keyOID, KeyUsage keyUsage); 

		// сгенерировать пару ключей
		protected: virtual NKeyHandle^ Generate(Container^ container, 
			String^ keyOID, DWORD keyType, BOOL exportable) = 0; 

		// сгенерировать пару ключей
		protected: NKeyHandle^ Generate(Container^ container, String^ alg, 
			DWORD keyType, BOOL exportable, Action<Handle^>^ action, DWORD flags
		); 
    };
}}}