#pragma once
#include "RFC4357.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace Wrap
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования ключа ГОСТ 28147-89 без диверсификации
	///////////////////////////////////////////////////////////////////////////
	public ref class RFC4357_NONE : RFC4357
	{
		// конструктор
		public: RFC4357_NONE(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			
            // сохранить переданные параметры
			String^ sboxOID, array<BYTE>^ ukm) : RFC4357(provider, hContext, sboxOID, ukm) {}

		// идентификатор алгоритма 
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_SIMPLE_EXPORT; } }

	    // получить алгоритм диверсификации ключа
		public: virtual CAPI::KeyDerive^ GetKDFAlgorithm(CAPI::CSP::ContextHandle^ hContext) override 
		{ 
			// диверсификация ключа отсутствует
			return gcnew CAPI::Derive::NOKDF(GOST::Engine::GOST28147::Endian); 
		}
    }; 
}}}}}
