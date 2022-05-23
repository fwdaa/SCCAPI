#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования DESX
	///////////////////////////////////////////////////////////////////////////
	public ref class DESX : CAPI::CSP::BlockCipher
	{
		// конструктор
		public: DESX(CAPI::CSP::Provider^ provider) 

            // сохранить переданные параметры
			: CAPI::CSP::BlockCipher(provider, provider->Handle) {} 

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return ANSI::Keys::DESX::Instance; }
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8; }}
	};
}}}}}
