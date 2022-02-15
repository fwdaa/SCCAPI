#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class VerifyHash : ANSI::CSP::Microsoft::Sign::RSA::VerifyHash
	{
		// конструктор
		public: VerifyHash(CAPI::CSP::Provider^ provider) 
			
			// сохранить переданные параметры
			: ANSI::CSP::Microsoft::Sign::RSA::VerifyHash(provider) {} 
	};
}}}}}}}
