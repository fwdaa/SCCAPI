#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования TDES
	///////////////////////////////////////////////////////////////////////////
	public ref class TDES : CAPI::CSP::BlockCipher
	{
		// конструктор
		public: TDES(CAPI::CSP::Provider^ provider, array<int>^ keySizes) 

            // сохранить переданные параметры
			: CAPI::CSP::BlockCipher(provider, provider->Handle) 
		
			// сохранить переданные параметры
			{ this->keySizes = keySizes; } private: array<int>^ keySizes; 

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return Keys::TDES::Instance; }
		}
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
		{ 
			// размер ключа в байтах
			array<int>^ get() override { return keySizes; } 
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8; }}
	};
}}}}}}
