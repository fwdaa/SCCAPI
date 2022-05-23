#pragma once
#include "RFC4357.h"
#include "..\Cipher\GOST28147.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace Wrap
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования ключа ГОСТ 28147-89 c диверсификацией
	///////////////////////////////////////////////////////////////////////////
	public ref class RFC4357_CPRO : RFC4357
	{
		// конструктор
		public: RFC4357_CPRO(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			
            // сохранить переданные параметры
			String^ sboxOID, array<BYTE>^ ukm) : RFC4357(provider, hContext, sboxOID, ukm) {}

		// идентификатор алгоритма 
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_PRO_EXPORT; } }

	    // получить алгоритм диверсификации ключа
		public: virtual CAPI::KeyDerive^ GetKDFAlgorithm(CAPI::CSP::ContextHandle^ hContext) override
        {
			// создать блочный алгоритм шифрования
			Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(
				Provider, hContext, SBoxOID, ASN1::GOST::OID::keyMeshing_none
			)); 
            // создать алгоритм диверсификации ключа
            return gcnew CAPI::GOST::Derive::RFC4357(blockCipher.Get()); 
        } 
	};
}}}}}
