#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования блока DES
	///////////////////////////////////////////////////////////////////////////////
	public ref class DES : CAPI::CNG::BlockCipher
	{
		// конструктор
		public: DES(String^ provider) : CAPI::CNG::BlockCipher(provider) {}
		 
        // имя алгоритма шифрования
		public: virtual String^ GetName(int keySize) override { return BCRYPT_DES_ALGORITHM; }

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return Keys::DES::Instance; }
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8; }} 
	};
}}}}}}
