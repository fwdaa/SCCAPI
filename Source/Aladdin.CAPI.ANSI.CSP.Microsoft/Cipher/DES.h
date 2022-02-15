#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования DES
	///////////////////////////////////////////////////////////////////////////
	public ref class DES : CAPI::CSP::BlockCipher
	{
		// конструктор
		public: DES(CAPI::CSP::Provider^ provider) 

            // сохранить переданные параметры
			: CAPI::CSP::BlockCipher(provider, provider->Handle) {} 

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return Keys::DES::Instance; }
		}
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
		{ 
			// размер ключа в байтах
			array<int>^ get() override { return gcnew array<int> {8}; } 
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8; }}

		// создать режим шифрования
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode) override
		{
			// для режима CBC встроенная реализация может генерировать NTE_DOUBLE_ENCRYPT
			if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
			{
				// выполнить преобразование типа
				CipherMode::CBC^ parameters = (CipherMode::CBC^)mode; 

                // получить алгоритм шифрования блока
                Using<CAPI::Cipher^> engine(CreateBlockMode(gcnew CipherMode::ECB())); 
                
				// создать режим алгоритма
				return gcnew CAPI::Mode::CBC(engine.Get(), parameters, PaddingMode::Any); 
			}
			// вызвать базовую реализацию
			return CAPI::CSP::BlockCipher::CreateBlockMode(mode); 
		}
	};
}}}}}}
