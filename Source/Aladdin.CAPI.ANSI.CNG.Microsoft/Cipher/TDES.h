#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования блока TDES
	///////////////////////////////////////////////////////////////////////////////
	public ref class TDES : CAPI::CNG::BlockCipher
	{
		// размеры ключей
		private: array<int>^ keySizes; 

		// конструктор
		public: TDES(String^ provider, array<int>^ keySizes) 
			
			// сохранить переданные параметры
			: CAPI::CNG::BlockCipher(provider) { this->keySizes = keySizes; }
		 
        // имя алгоритма шифрования
		public: virtual String^ GetName(int keySize) override  
		{
			// имя алгоритма шифрования
			return (keySize == 24) ? BCRYPT_3DES_ALGORITHM : BCRYPT_3DES_112_ALGORITHM; 
		}
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
