#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования блока RC2
	///////////////////////////////////////////////////////////////////////////////
	public ref class RC2 : CAPI::CNG::BlockCipher
	{
		// эффективное число битов и размеры ключей
		private: int effectiveKeyBits; private: array<int>^ keySizes; 

		// конструктор
		public: RC2(String^ provider, int effectiveKeyBits, array<int>^ keySizes)
			
			// сохранить переданные параметры
			: CAPI::CNG::BlockCipher(provider) 
		{ 
			// сохранить переданные параметры
			this->effectiveKeyBits = effectiveKeyBits; this->keySizes = keySizes; 
		} 
        // имя алгоритма шифрования
		public: virtual String^ GetName(int keySize) override { return BCRYPT_RC2_ALGORITHM; }

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return gcnew Keys::RC2(keySizes); }
		}
		// размер блока и ключа по умолчанию
		public: virtual property int BlockSize  { int get() override { return 8; }} 

		// установить параметры алгоритма
		public: virtual void SetParameters(CAPI::CNG::BProviderHandle^ hKey) override
		{
			// указать параметр алгоритма
			hKey->SetLong(BCRYPT_EFFECTIVE_KEY_LENGTH, effectiveKeyBits, 0); 
		}
	};
}}}}}}
