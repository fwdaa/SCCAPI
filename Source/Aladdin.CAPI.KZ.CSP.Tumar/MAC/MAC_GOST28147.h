#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки ГОСТ 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST28147 : CAPI::CSP::Mac
	{
		// конструктор
		public: GOST28147(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			
			// сохранить переданные параметры
			String^ sboxOID) : CAPI::CSP::Mac(provider, hContext, 0) 
		
			// сохранить переданные параметры
			{ this->sboxOID = sboxOID; } private: String^ sboxOID;

        // идентификатор алгоритма
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_GOST_IMIT; }}

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return GOST::Keys::GOST28147::Instance; }
		}
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
		{ 
			// размер ключа в байтах
			array<int>^ get() override { return gcnew array<int> {32}; }
		}
		// размер имитовставки
		public: virtual property int MacSize { int get() override { return 8;  }}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8;  }}

		// установить параметры алгоритма шифрования
		protected: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override; 
	};
}}}}}}

