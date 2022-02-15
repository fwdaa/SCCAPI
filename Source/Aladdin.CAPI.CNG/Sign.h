#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	ref class BSign; ref class NSign; 

	///////////////////////////////////////////////////////////////////////////
	// Алгоритм подписи хэш-значения
	///////////////////////////////////////////////////////////////////////////
	public ref class BSignHash abstract : CAPI::SignHash
	{
		private: String^ provider;	// имя провайдера

		// конструктор
		protected: BSignHash(String^ provider) { this->provider = provider; }
			
		// имя алгоритма
		protected: virtual String^ GetName(IParameters^ parameters) = 0; 

		// импортировать личный ключ
		protected: virtual BKeyHandle^ ImportPrivateKey(
			BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) = 0; 

		// подписать хэш-значение
		protected: virtual array<BYTE>^ Sign(IParameters^ parameters, BKeyHandle^ hPrivateKey,  
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
		{
			// подписать хэш-значение
			return hPrivateKey->SignHash(IntPtr::Zero, hash, 0);
		}
		// алгоритм подписи хэш-значения
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;
	};
	public ref class BVerifyHash abstract : CAPI::VerifyHash
	{
		private: String^ provider;	// имя провайдера

		// конструктор
		protected: BVerifyHash(String^ provider) { this->provider = provider; }
			
		// имя алгоритма
		protected: virtual String^ GetName(IParameters^ parameters) = 0; 

		// импортировать открытый ключ
		protected: virtual BKeyHandle^ ImportPublicKey(
			BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) = 0; 

		// алгоритм проверки подписи хэш-значения
		protected: virtual void Verify(IParameters^ parameters, BKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
		{
			// проверить подпись хэш-значения
			hPublicKey->VerifySignature(IntPtr::Zero, hash, signature, 0);   
		}
		// алгоритм проверки подписи хэш-значения
		public: virtual void Verify(IPublicKey^ publicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
			array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
	public ref class NSignHash abstract : CAPI::SignHash
	{
		// подписать хэш-значение
		protected: array<BYTE>^ Sign(SecurityObject^ scope, 
			NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ hash, DWORD flags
		); 
		// подписать хэш-значение
		protected: virtual array<BYTE>^ Sign(SecurityObject^ scope, IParameters^ parameters, 
			NKeyHandle^ hPrivateKey, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
		{
			// подписать хэш-значение
			return Sign(scope, hPrivateKey, IntPtr::Zero, hash, 0);
		}
		// алгоритм подписи хэш-значения
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;
	};
	public ref class NVerifyHash abstract : CAPI::VerifyHash
	{
		// конструктор
		protected: NVerifyHash(NProvider^ provider) 
		
			// сохранить переданные параметры
			{ this->provider = RefObject::AddRef(provider); } private: NProvider^ provider; 

		// деструктор
		public: virtual ~NVerifyHash() { RefObject::Release(provider); }

		// алгоритм проверки подписи хэш-значения
		protected: virtual void Verify(IParameters^ parameters, NKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
		{
			// проверить подпись хэш-значения
			hPublicKey->VerifySignature(IntPtr::Zero, hash, signature, 0);   
		}
		// алгоритм проверки подписи хэш-значения
		public: virtual void Verify(IPublicKey^ publicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
			array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
}}}