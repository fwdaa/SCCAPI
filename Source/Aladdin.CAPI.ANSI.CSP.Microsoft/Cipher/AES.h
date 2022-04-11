#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования AES-128
	///////////////////////////////////////////////////////////////////////////
	public ref class AES : CAPI::CSP::BlockCipher
	{
		private: array<int>^ keySizes; 

		// конструктор
		public: AES(CAPI::CSP::Provider^ provider, array<int>^ keySizes) 

            // сохранить переданные параметры
			: CAPI::CSP::BlockCipher(provider, provider->Handle) { this->keySizes = keySizes; } 

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return gcnew Keys::AES(keySizes); }
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 16; }}
	};
}}}}}}
