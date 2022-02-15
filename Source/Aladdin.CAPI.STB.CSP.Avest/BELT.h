#pragma once

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP { namespace BelT
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования BELT
	///////////////////////////////////////////////////////////////////////////
	public ref class Hash : CAPI::CSP::Hash
	{
		// конструктор
		public: Hash(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext) 

			// сохранить переданные параметры
			: CAPI::CSP::Hash(provider, hContext) {}

        // идентификатор алгоритма
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_BELT_HASH; }}

		// размер блока и хэш-значения
		public: virtual property int BlockSize { int get() override { return 32; } }
		public: virtual property int HashSize  { int get() override { return 32; } }

		// создать алгоритм хэширования
		public protected: virtual CAPI::CSP::HashHandle Construct() override
		{
			// создать алгоритм хэширования
			return CAPI::CSP::Hash::Construct(); 
		} 
	};
}}}}}}