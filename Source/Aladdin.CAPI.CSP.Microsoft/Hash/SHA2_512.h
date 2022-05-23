#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Hash 
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования SHA-512
	///////////////////////////////////////////////////////////////////////////
	public ref class SHA2_512 : CAPI::CSP::Hash
	{
		// конструктор
		public: SHA2_512(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext)
			
			// сохранить переданные параметры
			: CAPI::CSP::Hash(provider, hContext) {} 

        // идентификатор алгоритма
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_SHA_512; }}

		// размер хэш-значения и блока в байтах
		public: virtual property int HashSize  { int get() override { return  64; } }  
		public: virtual property int BlockSize { int get() override { return 128; } }   
	};
}}}}}
