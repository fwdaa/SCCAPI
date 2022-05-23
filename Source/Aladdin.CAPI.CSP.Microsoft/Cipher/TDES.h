#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования TDES
	///////////////////////////////////////////////////////////////////////////
	public ref class TDES : CAPI::CSP::BlockCipher
	{
		// конструктор
		public: TDES(CAPI::CSP::Provider^ provider, array<int>^ keySizes) 

            // сохранить переданные параметры
			: CAPI::CSP::BlockCipher(provider, provider->Handle) 
		
			// сохранить переданные параметры
			{ this->keySizes = keySizes; } private: array<int>^ keySizes; 

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return gcnew ANSI::Keys::TDES(keySizes); }
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8; }}
	};
}}}}}
