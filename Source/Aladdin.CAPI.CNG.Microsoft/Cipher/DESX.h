#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Cipher
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
			SecretKeyFactory^ get() override { return ANSI::Keys::DESX::Instance; }
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return  8; }}
	};
}}}}}
