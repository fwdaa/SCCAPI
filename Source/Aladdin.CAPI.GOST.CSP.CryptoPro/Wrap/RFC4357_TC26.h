#pragma once
#include "RFC4357.h"
#include "..\MAC\HMAC_GOSTR3411_2012.h"


namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Wrap
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования ключа ГОСТ 28147-89 c диверсификацией
	///////////////////////////////////////////////////////////////////////////
	public ref class RFC4357_TC26 : RFC4357
	{
		// конструктор
		public: RFC4357_TC26(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			String^ sboxOID, array<BYTE>^ ukm) 
			
            // сохранить переданные параметры
			: RFC4357(provider, hContext, sboxOID, ukm) {}

		// идентификатор алгоритма 
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_PRO12_EXPORT; } }

	    // получить алгоритм диверсификации ключа
        public: virtual KeyDerive^ GetKDFAlgorithm(CAPI::CSP::ContextHandle^ hContext) override
        {
            // создать алгоритм вычисления имитовставки
            Using<CAPI::CSP::Mac^> hmac(gcnew MAC::HMAC_GOSTR3411_2012(Provider, hContext, 256)); 

            // указать значение label
            array<BYTE>^ label = gcnew array<BYTE> { 0x26, 0xBD, 0xB8, 0x78 }; 

            // создать алгоритм диверсификации ключа
            return gcnew Derive::TC026(hmac.Get(), label);
        } 
	};
}}}}}}
