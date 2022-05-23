#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class VerifyHash : Microsoft::Sign::RSA::VerifyHash
	{
		// конструктор
		public: VerifyHash(CAPI::CSP::Provider^ provider) 
			
			// сохранить переданные параметры
			: Microsoft::Sign::RSA::VerifyHash(provider) {} 
	};
}}}}}}
