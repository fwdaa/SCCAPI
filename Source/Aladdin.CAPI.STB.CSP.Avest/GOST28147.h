#pragma once

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP { namespace GOST28147
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования блока ГОСТ 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockEngine : CAPI::CSP::BlockEngine
	{
		// конструктор
		public: BlockEngine(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext) 

            // сохранить переданные параметры
            : CAPI::CSP::BlockEngine(provider, hContext) {} 

        // идентификатор алгоритма шифрования
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_G28147; }}

		// размер блока
		public: virtual property int BlockSize { int get() override { return  8; }}

		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
        { 
		    // размер ключа в байтах
            array<int>^ get() override { return gcnew array<int> { 32 }; } 
        }
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования ГОСТ 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockCipher : CAPI::CSP::BlockCipher
	{
		private: String^ sboxOID;	// идентификатор таблицы подстановок

		// конструктор
		public: BlockCipher(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext, 
            String^ sboxOID, CipherMode mode, CAPI::PaddingMode padding, array<BYTE>^ iv) 
				: CAPI::CSP::BlockCipher(gcnew GOST28147::BlockEngine(provider, hContext), mode, padding, iv) 
		{
			this->sboxOID = sboxOID;	// идентификатор таблицы подстановок
		} 
        // идентификатор алгоритма шифрования
		public: virtual property ALG_ID AlgID { ALG_ID get() override 
        { 
            // идентификатор алгоритма шифрования
            return (Padding == PaddingMode::PKCS7) ? CALG_G28147_PADDED : CALG_G28147; 
        }}
		// установить параметры алгоритма шифрования
		public protected: virtual void SetParameters(CAPI::CSP::KeyHandle hKey) override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки ГОСТ 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class Imito : CAPI::CSP::Mac
	{
		private: String^ sboxOID;	// идентификатор таблицы подстановок

		// конструктор
		public: Imito(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext, 
            String^ sboxOID) : CAPI::CSP::Mac(provider, hContext) 
		{
			this->sboxOID = sboxOID;	// идентификатор таблицы подстановок
		}
        // идентификатор ключа алгоритма 
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_G28147_MAC; }}
        // идентификатор ключа алгоритма 
		protected: virtual property ALG_ID KeyAlgID { ALG_ID get() override { return CALG_G28147; }}

		// размер имитовставки
		public: virtual property int HashSize { int get() override { return 4;  }}

		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
        { 
		    // размер ключа в байтах
            array<int>^ get() override { return gcnew array<int> { 32 }; } 
        }
		// установить параметры алгоритма шифрования
		public protected: virtual void SetParameters(CAPI::CSP::KeyHandle hKey) override; 
	}; 
}}}}}}
