#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования ГОСТ Р 34.11-1994
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST34311 : CAPI::CSP::Hash
	{
		// конструктор
		public: GOST34311(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, ALG_ID algID) 

			// сохранить переданные параметры
			: CAPI::CSP::Hash(provider, hContext) { this->algID = algID; } private: ALG_ID algID; 

        // идентификатор алгоритма
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return algID; }}

		// размер блока и хэш-значения
		public: virtual property int BlockSize { int get() override { return 32; }}
		public: virtual property int HashSize  { int get() override { return 32; }}
	};
}}}}}
