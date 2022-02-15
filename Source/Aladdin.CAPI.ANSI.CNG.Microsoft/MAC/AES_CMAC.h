#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки AES GMAC
	///////////////////////////////////////////////////////////////////////////
	public ref class AES_CMAC : CAPI::CNG::Mac
	{
		// конструктор
		public: AES_CMAC(String^ provider, array<int>^ keySizes) 
			: CAPI::CNG::Mac(provider, "AES-CMAC", 0) 

			// сохранить переданные параметры
			{ this->keySizes = keySizes; } private: array<int>^ keySizes; 

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return Keys::AES::Instance; }
		}
		// размер допустимых ключей
		public: virtual property array<int>^ KeySizes 
		{ 
			// размер допустимых ключей
			array<int>^ get() override { return keySizes; }
		}
		// размер блока в байтах
		public:	virtual property int BlockSize { int get() override { return 16; } }
	};
}}}}}}
