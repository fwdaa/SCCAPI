#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования блока AES
	///////////////////////////////////////////////////////////////////////////////
	public ref class AES : CAPI::CNG::BlockCipher
	{
		// размеры используемых ключей
		private: array<int>^ keySizes; 

		// конструктор
		public: AES(String^ provider, array<int>^ keySizes) 
			
			// сохранить переданные параметры
			: CAPI::CNG::BlockCipher(provider) { this->keySizes = keySizes; } 
		 
        // имя алгоритма шифрования
		public: virtual String^ GetName(int keySize) override { return BCRYPT_AES_ALGORITHM; }

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
