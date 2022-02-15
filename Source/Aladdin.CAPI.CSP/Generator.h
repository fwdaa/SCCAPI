#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	//////////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	//////////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator abstract : CAPI::KeyPairGenerator
    {
		// параметры ключей
		private: IParameters^ parameters; 

		// конструктор
		public: KeyPairGenerator(CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, IParameters^ parameters) 
			
			// сохранить переданные параметры
			: CAPI::KeyPairGenerator(provider, scope, rand) { this->parameters = parameters; }

        // используемый провайдер
		public: property CSP::Provider^ Provider 
		{ 
			// используемый провайдер
			CSP::Provider^ get() { return (CSP::Provider^)Factory; }
		}
        // параметры генерации
		public: property IParameters^ Parameters { IParameters^ get() { return parameters; }}

		// сгенерировать пару ключей
		public: virtual KeyPair^ Generate(array<BYTE>^ keyID, 
			String^ keyOID, KeyUsage keyUsage, KeyFlags keyFlags) override; 

		// сгенерировать пару ключей
		public: virtual KeyPair^ Generate(String^ keyOID, KeyUsage keyUsage); 

		// сгенерировать пару ключей
		protected: virtual KeyHandle^ Generate(Container^ container, 
			String^ keyOID, DWORD keyType, DWORD keyFlags) = 0; 

		// сгенерировать пару ключей
		protected: KeyHandle^ Generate(Container^ container, ALG_ID algID, DWORD flags); 
	};
}}}