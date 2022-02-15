#pragma once
#include "..\..\Hash\GOSTR3411_1994.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Sign { namespace GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Подпись данных ГОСТ Р 34.10-2001
    ///////////////////////////////////////////////////////////////////////////
	public ref class VerifyData2001 : GOST::Sign::GOSTR3410::VerifyData2001
	{
		// используемый провайдер
		private: CAPI::CSP::Provider^ provider; 

	    // конструктор
		public: VerifyData2001(CAPI::CSP::Provider^ provider, CAPI::VerifyHash^ signAlgorithm) 
			
			// сохранить переданные параметры
			: GOST::Sign::GOSTR3410::VerifyData2001(signAlgorithm) 
		{
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); 
		}
		// деструктор
		public: virtual ~VerifyData2001() { RefObject::Release(provider); }

		// получить алгоритм хэширования
		protected: virtual CAPI::Hash^ CreateHashAlgorithm(String^ hashOID) override
		{
			// создать алгоритм хэширования
			return gcnew Hash::GOSTR3411_1994(provider, provider->Handle, hashOID); 
		}
	}; 
}}}}}}}
