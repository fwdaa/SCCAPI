#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки ГОСТ 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST28147 : CAPI::CSP::Mac
	{
		private: String^		sboxOID;	// идентификатор таблицы подстановок
		private: String^ 		meshing;	// режим смены ключа
		private: array<BYTE>^	start;		// стартовое значение 

		// конструктор
		public: GOST28147(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 

			// сохранить переданные параметры
			String^ sboxOID, String^ meshing, array<BYTE>^ start) : CAPI::CSP::Mac(provider, hContext, 0) 
		{
			this->sboxOID	= sboxOID;	// идентификатор таблицы подстановок
			this->meshing	= meshing;	// режим смены ключа
			this->start		= start;	// стартовое значение 
		}
        // идентификатор алгоритма
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_G28147_MAC; }}

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return GOST::Keys::GOST::Instance; }
		}
		// размер имитовставки
		public: virtual property int MacSize { int get() override { return 4;  }}
		// размер блока
		public: virtual property int BlockSize { int get() override { return 8;  }}

		// установить параметры алгоритма шифрования
		protected: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override; 

		// создать алгоритм хэширования
		protected: virtual CAPI::CSP::HashHandle^ Construct(
			CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) override; 
	}; 
}}}}}
