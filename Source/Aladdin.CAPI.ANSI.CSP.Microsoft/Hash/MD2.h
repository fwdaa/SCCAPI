#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Hash 
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования MD2
	///////////////////////////////////////////////////////////////////////////
	public ref class MD2 : CAPI::CSP::Hash
	{
		// конструктор
		public: MD2(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext) 
			
			// сохранить переданные параметры
			: CAPI::CSP::Hash(provider, hContext) {} 

        // идентификатор алгоритма
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_MD2; }}

		// размер хэш-значения и блока в байтах
		public: virtual property int HashSize  { int get() override { return 16; } }  
		public: virtual property int BlockSize { int get() override { return 16; }}   
	};
}}}}}}


