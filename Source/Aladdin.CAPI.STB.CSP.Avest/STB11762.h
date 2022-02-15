#pragma once

#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP { namespace STB11762
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ DSA
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::STB::Avest::STB11762::IPrivateKey
	{
		// конструктор
		public: PrivateKey(CAPI::CSP::Provider^ provider, IKeyFactory^ keyFactory, 
			CAPI::CSP::KeyHandle hKeyPair, DWORD keyType)
			: CAPI::CSP::PrivateKey(provider, keyFactory, hKeyPair, keyType) {} 

		// конструктор
		public: PrivateKey(CAPI::CSP::Container^ container, IKeyFactory^ keyFactory, 
			CAPI::CSP::KeyHandle hKeyPair, DWORD keyType)
			: CAPI::CSP::PrivateKey(container, keyFactory, hKeyPair, keyType) {} 

		// личный ключ подписи
		public: virtual property STB::STB11762::IPrivateKey^ Sign 
		{
			// ключ не является экспортируемым
			STB::STB11762::IPrivateKey^ get() { throw gcnew CryptographicException(NTE_BAD_KEY); }
		} 
		// личный ключ обмена	
		public: virtual property STB::STB11762::IPrivateKey^ KeyX	
		{
			// ключ не является экспортируемым
			STB::STB11762::IPrivateKey^ get() { throw gcnew CryptographicException(NTE_BAD_KEY); }
		}
	};
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// конструктор
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, IKeyFactory^ keyFactory) 
			: CAPI::CSP::KeyPairGenerator(provider, keyFactory) {}
		
		// сгенерировать пару ключей
		protected: virtual CAPI::CSP::KeyHandle Generate(
			CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags) override; 
	}; 
    ///////////////////////////////////////////////////////////////////////
	// Алгоритм подписи хэш-значения СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////
    public ref class SignHash : CAPI::CSP::SignHash
	{
		// конструктор
		public: SignHash(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::SignHash(provider) {} 

		// идентификатор алгоритма
		protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// идентификатор алгоритма
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// создать алгоритм хэширования
		protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAgorithm) override;
	};
    public ref class VerifyHash : CAPI::CSP::VerifyHash
	{
		// конструктор
		public: VerifyHash(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::VerifyHash(provider) {} 

		// идентификатор алгоритма
		protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// идентификатор алгоритма
			return ((CSP::Provider^)provider)->SignID; 
		}} 
		// создать алгоритм хэширования
		protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAgorithm) override;
	};
    ///////////////////////////////////////////////////////////////////////
	// Алгоритм подписи данных СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////
    public ref class SignDataSTB11761 : CAPI::CSP::SignData
    {
		// конструктор
		public: SignDataSTB11761(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::SignData(provider) {} 

		// идентификатор алгоритма
		public protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// идентификатор алгоритма
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// создать алгоритм хэширования
		public protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory) override; 
	}; 
    public ref class VerifyDataSTB11761 : CAPI::CSP::VerifyData
    {
		// конструктор
		public: VerifyDataSTB11761(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::VerifyData(provider) {} 

		// идентификатор алгоритма
		public protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// идентификатор алгоритма
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// создать алгоритм хэширования
		public protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory) override; 
	}; 
    ///////////////////////////////////////////////////////////////////////
	// Алгоритм подписи данных СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////
    public ref class SignDataBelT : CAPI::CSP::SignData
    {
		// конструктор
		public: SignDataBelT(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::SignData(provider) {} 

		// идентификатор алгоритма
		public protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// идентификатор алгоритма
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// создать алгоритм хэширования
		public protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory) override; 
	}; 
    public ref class VerifyDataBelT : CAPI::CSP::VerifyData
    {
		// конструктор
		public: VerifyDataBelT(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::VerifyData(provider) {} 

		// идентификатор алгоритма
		public protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// идентификатор алгоритма
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// создать алгоритм хэширования
		public protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory) override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм обмена СТБ 1176.2
	///////////////////////////////////////////////////////////////////////////
	public ref class ASN1KeyWrap : IASN1KeyWrap
	{
		// конструктор
		public: ASN1KeyWrap(CAPI::CSP::Provider^ provider) 
		
			// сохранить переданные параметры
			{ this->provider = provider; } private: CAPI::CSP::Provider^ provider;

		// действия стороны-отправителя
		public: virtual ASN1TransportData^ Wrap(IPublicKey^ publicKey, IRand^ rand, IKey^ CEK); 
	}; 
	public ref class ASN1KeyUnwrap : IASN1KeyUnwrap
	{
		// конструктор
		public: ASN1KeyUnwrap(CAPI::CSP::Provider^ provider) 
		
			// сохранить переданные параметры
			{ this->provider = provider; } private: CAPI::CSP::Provider^ provider;

		// действия стороны-получателя
		public: virtual IKey^ Unwrap(IPrivateKey^ privateKey, ASN1TransportData^ transportData); 
	}; 
}}}}}}
