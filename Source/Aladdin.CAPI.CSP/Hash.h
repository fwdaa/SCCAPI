#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования
	///////////////////////////////////////////////////////////////////////
	public ref class Hash abstract : CAPI::Hash
	{
		private: CSP::Provider^		provider;	// криптографический провайдер 
		private: ContextHandle^		hContext;	// криптографический контекст 
		private: Using<HashHandle^>	hHash;		// алгоритм хэширования 
		
		// конструктор
		protected: Hash(CSP::Provider^ provider, ContextHandle^ hContext)
		{ 
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); 
			
			// сохранить переданные параметры
			this->hContext = Handle::AddRef(hContext); 
		}
		// деструктор
        public: virtual ~Hash() 
		{ 
			// освободить выделенные ресурсы
			Handle::Release(hContext); RefObject::Release(provider); 
		} 
        // криптографический провайдер и контекст
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
    
		// идентификатор алгоритма
		public: virtual property ALG_ID AlgID { ALG_ID get() = 0; }

		// создать алгоритм хэширования
		protected: virtual HashHandle^ Construct()
		{
			// создать алгоритм хэширования
			return hContext->CreateHash(AlgID, nullptr, 0); 
		} 
		// инициализировать алгоритм
		public: virtual void Init() override;  
		// захэшировать данные
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override; 
		// получить хэш-значение
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override; 
	};
}}}