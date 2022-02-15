#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования AES-192
	///////////////////////////////////////////////////////////////////////////
	public ref class AES192 : CAPI::CSP::BlockCipher
	{
		// конструктор
		public: AES192(CAPI::CSP::Provider^ provider) 

            // сохранить переданные параметры
			: CAPI::CSP::BlockCipher(provider, provider->Handle) {} 

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return Keys::AES::Instance; }
		}
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
		{ 
			// размер ключа в байтах
			array<int>^ get() override { return gcnew array<int> {24}; } 
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 16; }}
	};
}}}}}}
