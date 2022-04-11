#pragma once
#include "..\MAC\MAC_GOST28147.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// Блочный алгоритм шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST28147 : CAPI::CSP::BlockCipher
	{
		// идентификатор таблицы подстановок и признак смены ключа
		private: String^ sboxOID; private: bool meshing; 

		// конструктор
		public: GOST28147(CAPI::CSP::Provider^ provider, 
			CAPI::CSP::ContextHandle^ hContext, String^ sboxOID, bool meshing)

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
			SecretKeyFactory^ get() override { return GOST::Keys::GOST::Instance; }
		}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8; }} 

		// создать режим шифрования
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode) override; 

		// установить параметры алгоритма
		public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override; 

		///////////////////////////////////////////////////////////////////////////
		// Алгоритм шифрования ГОСТ 28147-89
		///////////////////////////////////////////////////////////////////////////
		public: ref class BlockMode : CAPI::CSP::BlockMode
		{
			// конструктор
			public: BlockMode(CAPI::CSP::BlockCipher^ blockCipher, CipherMode^ mode, PaddingMode padding) 

				// сохранить переданные параметры
				: CAPI::CSP::BlockMode(blockCipher, mode, padding) {} 

			// установить параметры алгоритма шифрования
			public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey, PaddingMode padding) override;

			// алгоритм зашифрования данных
			protected: virtual Transform^ CreateEncryption(ISecretKey^ key) override
			{
				// получить преобразовние зашифрования
				return gcnew CAPI::CSP::Encryption(this, PaddingMode::None, key); 
			}
			// алгоритм расшифрования данных
			protected: virtual Transform^ CreateDecryption(ISecretKey^ key) override
			{
				// получить преобразовние зашифрования
				return gcnew CAPI::CSP::Decryption(this, PaddingMode::None, key); 
			}
		};
	};
}}}}}}
