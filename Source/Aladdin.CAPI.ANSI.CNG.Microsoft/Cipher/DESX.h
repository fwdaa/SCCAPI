#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования DESX
	///////////////////////////////////////////////////////////////////////////
	public ref class DESX : CAPI::CNG::BlockCipher
	{
		// конструктор
		public: DESX(String^ provider) : CAPI::CNG::BlockCipher(provider) {}
			
        // имя алгоритма шифрования
		public: virtual String^ GetName(int keySize) override { return BCRYPT_DESX_ALGORITHM; }

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return Keys::DESX::Instance; }
		}
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
		{ 
			// размер ключа в байтах
			array<int>^ get() override { return gcnew array<int> {24}; }
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return  8; }}
	};
}}}}}}
