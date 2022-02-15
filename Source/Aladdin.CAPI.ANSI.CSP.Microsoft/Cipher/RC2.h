#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования RC2
	///////////////////////////////////////////////////////////////////////////
	public ref class RC2 : CAPI::CSP::BlockCipher
	{
		// эффективное число битов и размер ключей
		private: DWORD effectiveKeyBits; private: array<int>^ keySizes; 

		// конструктор
		public: RC2(CAPI::CSP::Provider^ provider, int effectiveKeyBits, array<int>^ keySizes) 

            // сохранить переданные параметры
			: CAPI::CSP::BlockCipher(provider, provider->Handle) 
		{ 
			// сохранить переданные параметры
			this->effectiveKeyBits = effectiveKeyBits; this->keySizes = keySizes; 
		} 
		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return Keys::RC2::Instance; }
		}
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
		{ 
			// размер ключа в байтах
			array<int>^ get() override { return keySizes; }
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8; }}

		// установить параметры алгоритма
		public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override
		{
			// указать параметр алгоритма
			hKey->SetLong(KP_EFFECTIVE_KEYLEN, effectiveKeyBits, 0); 
		}
	};
}}}}}}
