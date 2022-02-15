#pragma once

#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP { namespace STB11762
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ���� DSA
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::STB::Avest::STB11762::IPrivateKey
	{
		// �����������
		public: PrivateKey(CAPI::CSP::Provider^ provider, IKeyFactory^ keyFactory, 
			CAPI::CSP::KeyHandle hKeyPair, DWORD keyType)
			: CAPI::CSP::PrivateKey(provider, keyFactory, hKeyPair, keyType) {} 

		// �����������
		public: PrivateKey(CAPI::CSP::Container^ container, IKeyFactory^ keyFactory, 
			CAPI::CSP::KeyHandle hKeyPair, DWORD keyType)
			: CAPI::CSP::PrivateKey(container, keyFactory, hKeyPair, keyType) {} 

		// ������ ���� �������
		public: virtual property STB::STB11762::IPrivateKey^ Sign 
		{
			// ���� �� �������� ��������������
			STB::STB11762::IPrivateKey^ get() { throw gcnew CryptographicException(NTE_BAD_KEY); }
		} 
		// ������ ���� ������	
		public: virtual property STB::STB11762::IPrivateKey^ KeyX	
		{
			// ���� �� �������� ��������������
			STB::STB11762::IPrivateKey^ get() { throw gcnew CryptographicException(NTE_BAD_KEY); }
		}
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// �����������
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, IKeyFactory^ keyFactory) 
			: CAPI::CSP::KeyPairGenerator(provider, keyFactory) {}
		
		// ������������� ���� ������
		protected: virtual CAPI::CSP::KeyHandle Generate(
			CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags) override; 
	}; 
    ///////////////////////////////////////////////////////////////////////
	// �������� ������� ���-�������� ��� 1176.2
    ///////////////////////////////////////////////////////////////////////
    public ref class SignHash : CAPI::CSP::SignHash
	{
		// �����������
		public: SignHash(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::SignHash(provider) {} 

		// ������������� ���������
		protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// ������������� ���������
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// ������� �������� �����������
		protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAgorithm) override;
	};
    public ref class VerifyHash : CAPI::CSP::VerifyHash
	{
		// �����������
		public: VerifyHash(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::VerifyHash(provider) {} 

		// ������������� ���������
		protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// ������������� ���������
			return ((CSP::Provider^)provider)->SignID; 
		}} 
		// ������� �������� �����������
		protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAgorithm) override;
	};
    ///////////////////////////////////////////////////////////////////////
	// �������� ������� ������ ��� 1176.2
    ///////////////////////////////////////////////////////////////////////
    public ref class SignDataSTB11761 : CAPI::CSP::SignData
    {
		// �����������
		public: SignDataSTB11761(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::SignData(provider) {} 

		// ������������� ���������
		public protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// ������������� ���������
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// ������� �������� �����������
		public protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory) override; 
	}; 
    public ref class VerifyDataSTB11761 : CAPI::CSP::VerifyData
    {
		// �����������
		public: VerifyDataSTB11761(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::VerifyData(provider) {} 

		// ������������� ���������
		public protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// ������������� ���������
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// ������� �������� �����������
		public protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory) override; 
	}; 
    ///////////////////////////////////////////////////////////////////////
	// �������� ������� ������ ��� 1176.2
    ///////////////////////////////////////////////////////////////////////
    public ref class SignDataBelT : CAPI::CSP::SignData
    {
		// �����������
		public: SignDataBelT(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::SignData(provider) {} 

		// ������������� ���������
		public protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// ������������� ���������
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// ������� �������� �����������
		public protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory) override; 
	}; 
    public ref class VerifyDataBelT : CAPI::CSP::VerifyData
    {
		// �����������
		public: VerifyDataBelT(CAPI::CSP::Provider^ provider) 
			: CAPI::CSP::VerifyData(provider) {} 

		// ������������� ���������
		public protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// ������������� ���������
			return ((CSP::Provider^)Provider)->SignID; 
		}} 
		// ������� �������� �����������
		public protected: virtual CAPI::CSP::HashHandle CreateHash(
			CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory) override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// �������� ������ ��� 1176.2
	///////////////////////////////////////////////////////////////////////////
	public ref class ASN1KeyWrap : IASN1KeyWrap
	{
		// �����������
		public: ASN1KeyWrap(CAPI::CSP::Provider^ provider) 
		
			// ��������� ���������� ���������
			{ this->provider = provider; } private: CAPI::CSP::Provider^ provider;

		// �������� �������-�����������
		public: virtual ASN1TransportData^ Wrap(IPublicKey^ publicKey, IRand^ rand, IKey^ CEK); 
	}; 
	public ref class ASN1KeyUnwrap : IASN1KeyUnwrap
	{
		// �����������
		public: ASN1KeyUnwrap(CAPI::CSP::Provider^ provider) 
		
			// ��������� ���������� ���������
			{ this->provider = provider; } private: CAPI::CSP::Provider^ provider;

		// �������� �������-����������
		public: virtual IKey^ Unwrap(IPrivateKey^ privateKey, ASN1TransportData^ transportData); 
	}; 
}}}}}}
