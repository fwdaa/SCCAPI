#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм выработки имитовставки HMAC
	///////////////////////////////////////////////////////////////////////////
	public ref class HMAC : CAPI::CSP::Mac
	{
		// параметры алгоритма хэширования
		private: CAPI::CSP::Hash^ hashAlgorithm; 

		// конструктор
		public: HMAC(CAPI::CSP::Provider^ provider, CAPI::CSP::Hash^ hashAlgorithm) 

			// сохранить переданные параметры
			: CAPI::CSP::Mac(provider, provider->Handle, CRYPT_IPSEC_HMAC_KEY) 
        { 
			// сохранить переданные параметры
            this->hashAlgorithm = RefObject::AddRef(hashAlgorithm); 
        }
        // деструктор
		public: virtual ~HMAC() { RefObject::Release(hashAlgorithm); }
 
		// размер имитовставки
		public:	virtual property int MacSize 
		{ 
			// размер имитовставки
			int get() override { return hashAlgorithm->HashSize; }
		}  
		// размер блока
		public:	virtual property int BlockSize 
		{ 
			// размер блока
			int get() override { return hashAlgorithm->BlockSize; }
		}  
		// идентификатор алгоритма
		protected: virtual property ALG_ID AlgID    
		{ 
			// идентификатор алгоритма
			ALG_ID get() override { return CALG_HMAC; } 
		}
		// создать алгоритм вычисления имитовставки
		protected: virtual CAPI::CSP::HashHandle^ Construct(
			CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) override; 
	};
}}}}}
