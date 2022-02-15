#pragma once
#include "Provider.h"
#include "Key.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм подписи хэш-значения
	///////////////////////////////////////////////////////////////////////////
	public ref class SignHash abstract : CAPI::SignHash
	{
		// используемый провайдер
		private: CSP::Provider^ provider; DWORD flags; 

		// конструктор
		protected: SignHash(CSP::Provider^ provider, DWORD flags) 
		{ 		   
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); this->flags = flags; 
		} 
		// деструктор
		public: virtual ~SignHash() { RefObject::Release(provider); }

        // криптографический провайдер
		protected: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// создать алгоритм хэширования
		protected: virtual HashHandle^ CreateHash(ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ parameters) = 0; 

		// алгоритм подписи хэш-значения
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм проверки подписи хэш-значения
	///////////////////////////////////////////////////////////////////////////
	public ref class VerifyHash abstract : CAPI::VerifyHash
	{
		// используемый провайдер
		private: CSP::Provider^ provider; DWORD flags; 

		// конструктор
		protected: VerifyHash(CSP::Provider^ provider, DWORD flags) 
		{ 
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); this->flags = flags;
		} 
		// деструктор
		public: virtual ~VerifyHash() { RefObject::Release(provider); }

        // криптографический провайдер
		protected: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// создать алгоритм хэширования
		protected: virtual HashHandle^ CreateHash(ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ parameters) = 0; 

		// алгоритм проверки подписи хэш-значения
		public: virtual void Verify(IPublicKey^ publicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
			array<BYTE>^ hash, array<BYTE>^ signature) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм выработки подписи данных
	///////////////////////////////////////////////////////////////////////////
	public ref class SignData abstract : CAPI::SignData
	{
		private: CSP::Provider^		provider;	// криптографический провайдер 
		private: DWORD				flags;		// режим выполнения
		private: Using<HashHandle^>	hHash;		// алгоритм хэширования

		// конструктор
		protected: SignData(Provider^ provider, DWORD flags) 
		{ 
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); this->flags = flags;
		}
		// деструктор
		public: virtual ~SignData() { RefObject::Release(provider); } 

        // криптографический провайдер
		protected: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// создать алгоритм хэширования
		protected: virtual HashHandle^ CreateHash(
			ContextHandle^ hContext, IParameters^ parameters) = 0; 

		// инициализировать алгоритм
		public: virtual void Init(IPrivateKey^ privateKey, IRand^ rand) override; 
		// обработать данные
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override;
		// получить подпись данных
        public: virtual array<BYTE>^ Finish(IRand^ rand) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм проверки подписи данных
	///////////////////////////////////////////////////////////////////////////
	public ref class VerifyData abstract : CAPI::VerifyData
	{
		private: CSP::Provider^		provider;	// криптографический провайдер 
		private: DWORD				flags;		// режим выполнения
		private: Using<HashHandle^>	hHash;		// алгоритм хэширования

		// конструктор
		protected: VerifyData(Provider^ provider, DWORD flags) 
		{ 
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); this->flags = flags;
		}
		// деструктор
		public: virtual ~VerifyData() { RefObject::Release(provider); } 

        // криптографический провайдер
		protected: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// создать алгоритм хэширования
		protected: virtual HashHandle^ CreateHash(
			ContextHandle^ hContext, IParameters^ parameters) = 0; 

		// инициализировать алгоритм
		public: virtual void Init(IPublicKey^ publicKey, array<BYTE>^ signature) override; 
		// обработать данные
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override;
		// проверить подпись данных
		public: virtual void Finish() override;
	};
}}}