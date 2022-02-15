#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Keyx { namespace GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// Формирование общего ключа ГОСТ Р 34.10-2001, 2012
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyAgreement : CAPI::CSP::KeyAgreement
	{
		// конструктор
		public: KeyAgreement(CAPI::CSP::Provider^ provider, int sizeUKM) 
            : CAPI::CSP::KeyAgreement(provider, 0)
		 
            // сохранить переданные параметры
			{ this->sizeUKM = sizeUKM; } private: int sizeUKM;

		// сгенерировать случайные данные
		public: virtual array<BYTE>^ Generate(IParameters^ parameters, IRand^ rand) override
        {
            // выделить память для случайных данных
            array<BYTE>^ random = gcnew array<BYTE>(sizeUKM); 

            // сгенерировать случайные данные
            rand->Generate(random, 0, sizeUKM); return random; 
        } 
        // установить параметры ключа
        protected: virtual void SetKeyParameters(CAPI::CSP::ContextHandle^ hContext, 
            CAPI::CSP::KeyHandle^ hKey, array<BYTE>^ random, int keySize) override; 
	};
}}}}}}}
