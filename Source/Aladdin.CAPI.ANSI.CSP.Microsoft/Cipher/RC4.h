#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования RC4
	///////////////////////////////////////////////////////////////////////////
	public ref class RC4 : CAPI::CSP::Cipher
	{
		// конструктор
		public: RC4(CAPI::CSP::Provider^ provider, array<int>^ keySizes) 

            // сохранить переданные параметры
			: CAPI::CSP::Cipher(provider, provider->Handle) 
		 
            // сохранить переданные параметры
			{ this->keySizes = keySizes; } private: array<int>^ keySizes;

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return Keys::RC4::Instance; }
		}
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
		{ 
			// размер ключа в байтах
			array<int>^ get() override { return keySizes; } 
		}
	};
}}}}}}
