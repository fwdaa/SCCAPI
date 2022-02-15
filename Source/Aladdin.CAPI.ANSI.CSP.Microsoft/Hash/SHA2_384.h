#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Hash 
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования SHA-384
	///////////////////////////////////////////////////////////////////////////
	public ref class SHA2_384 : CAPI::CSP::Hash
	{
		// конструктор
		public: SHA2_384(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext)
			
			// сохранить переданные параметры
			: CAPI::CSP::Hash(provider, hContext) {} 

        // идентификатор алгоритма
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_SHA_384; }}

		// размер хэш-значения и блока в байтах
		public: virtual property int HashSize  { int get() override { return  48; } }  
		public: virtual property int BlockSize { int get() override { return 128; } }   
	};
}}}}}}
