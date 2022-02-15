#pragma once

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP { namespace STB11761
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования СТБ 1176.1
	///////////////////////////////////////////////////////////////////////////
	public ref class Hash : CAPI::CSP::Hash
	{
		private: array<BYTE>^ start; // стартовое значение

		// конструктор
		public: Hash(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext, array<BYTE>^ start) 

			// установить стартовое значение
			: CAPI::CSP::Hash(provider, hContext) { this->start = start; }
			
        // идентификатор алгоритма
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_BHF; }}

		// размер блока и хэш-значения
		public: virtual property int BlockSize { int get() override { return 32; } }
		public: virtual property int HashSize  { int get() override { return 32; } }

		// создать алгоритм хэширования
		public protected: virtual CAPI::CSP::HashHandle Construct() override; 
	};
}}}}}}
