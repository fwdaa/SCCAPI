#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Keyx { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class Decipherment : CAPI::CSP::Decipherment
	{
		// конструктор
		public: Decipherment(CAPI::CSP::Provider^ provider, DWORD flags) 

			// сохранить переданные параметры
			: CAPI::CSP::Decipherment(provider, flags) {} 

		// расшифровать данные
		public: virtual array<BYTE>^ Decrypt(IPrivateKey^ privateKey, array<BYTE>^ data) override
		{
			// сделать копию данных и изменить порядок байтов 
			data = (array<BYTE>^)data->Clone(); Array::Reverse(data);

			// расшифровать данные
			return CAPI::CSP::Decipherment::Decrypt(privateKey, data); 
		}
	};
}}}}}}}
