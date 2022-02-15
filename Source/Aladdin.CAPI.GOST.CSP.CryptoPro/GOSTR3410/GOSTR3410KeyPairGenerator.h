#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// конструктор
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, GOST::GOSTR3410::IECParameters^ parameters) 

			// сохранить переданные параметры
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) 

			// сохранить переданные параметры
			{ this->keyOID = keyOID; } private: String^ keyOID;
		
		// сгенерировать пару ключей
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
            String^ keyOID, DWORD keyType, DWORD keyFlags) override; 
	}; 
}}}}}}
