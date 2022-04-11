#pragma once
#include "..\MAC\MAC_GOST28147.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Блочный алгоритм шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST28147 : CAPI::CSP::BlockCipher
	{
		// идентификатор таблицы подстановок и способ смены ключа
		private: String^ sboxOID; private: String^ meshing;

		// конструктор
		public: GOST28147(CAPI::CSP::Provider^ provider, 
			CAPI::CSP::ContextHandle^ hContext, String^ sboxOID, String^ meshing)

			// сохранить переданные параметры
			: CAPI::CSP::BlockCipher(provider, hContext)
		{
			// сохранить переданные параметры
			this->sboxOID = sboxOID; this->meshing = meshing; 
		}
		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return Keys::GOST::Instance; }
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8; }} 

		// создать режим шифрования
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode) override; 

		// установить параметры алгоритма
		public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override; 

		///////////////////////////////////////////////////////////////////////////
		// Режим алгоритма шифрования ГОСТ 28147-89
		///////////////////////////////////////////////////////////////////////////
		public: ref class BlockMode : CAPI::CSP::BlockMode
		{
			// конструктор
			public: BlockMode(CAPI::CSP::BlockCipher^ blockCipher, CipherMode^ mode, 

				// сохранить переданные параметры
				PaddingMode padding) : CAPI::CSP::BlockMode(blockCipher, mode, padding) {}
			
			// установить параметры алгоритма шифрования
			public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey, PaddingMode padding) override;
		};
	};
}}}}}}
