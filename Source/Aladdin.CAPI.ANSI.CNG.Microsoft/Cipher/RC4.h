#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования RC4
	///////////////////////////////////////////////////////////////////////////
	public ref class RC4 : CAPI::CNG::Cipher
	{
		// конструктор
		public: RC4(String^ provider, array<int>^ keySizes) : CAPI::CNG::Cipher(provider) 
		
			// сохранить переданные параметры
			{ this->keySizes = keySizes; } private: array<int>^ keySizes; 

        // имя алгоритма шифрования
		public: virtual String^ GetName(int keySize) override { return BCRYPT_RC4_ALGORITHM; }

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return gcnew Keys::RC4(keySizes); }
		}
	};
}}}}}}
