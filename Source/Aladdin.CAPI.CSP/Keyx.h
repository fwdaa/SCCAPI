#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� �������� ����������
    ///////////////////////////////////////////////////////////////////////
	public ref class Encipherment abstract : CAPI::Encipherment
	{
		// ����������������� ���������
		private: Provider^ provider; private: DWORD flags; 

		// �����������
		protected: Encipherment(Provider^ provider, DWORD flags) 
		{
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); this->flags = flags; 
		} 
		// ����������
		public: virtual ~Encipherment() { RefObject::Release(provider);  }

        // ����������������� ���������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// ����������� ������
		public: virtual array<BYTE>^ Encrypt(IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data) override; 
	};
	public ref class Decipherment abstract : CAPI::Decipherment
	{
		// ����������������� ���������
		private: Provider^ provider; private: DWORD flags; 

		// �����������
		protected: Decipherment(Provider^ provider, DWORD flags) 
		{
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); this->flags = flags; 
		} 
		// ����������
		public: virtual ~Decipherment() { RefObject::Release(provider);  }

        // ����������������� ���������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// ������������ ������
		public: virtual array<BYTE>^ Decrypt(IPrivateKey^ privateKey, array<BYTE>^ data) override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// ������������ ������ �����
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyAgreement : CAPI::KeyAgreement
	{
		// ����������������� ��������� � ��������
		private: CAPI::CSP::Provider^ provider; private: DWORD flags; 

        // �����������
        protected: KeyAgreement(CAPI::CSP::Provider^ provider, DWORD flags) 
        {     
            // ��������� ���������� ���������
            this->provider = RefObject::AddRef(provider); this->flags = flags; 
        }
		// ����������
		public: virtual ~KeyAgreement() { RefObject::Release(provider);  }

		// ����������������� ���������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// ������������� ��������� ������
		public: virtual array<BYTE>^ Generate(IParameters^ parameters, IRand^ rand) override { return nullptr; }
 
	    // ����������� ����� ���� �� ������� ����������
		public: virtual ISecretKey^ DeriveKey(IPrivateKey^ privateKey, 
			IPublicKey^ publicKey, array<BYTE>^ random, 
			SecretKeyFactory^ keyFactory, int keySize) override;

        // ���������� ��������� �����
        protected: virtual void SetKeyParameters(ContextHandle^ hContext, 
			KeyHandle^ hKey, array<BYTE>^ random, int keySize) {}
	};
    ///////////////////////////////////////////////////////////////////////////
    // �������� ���������� �����
    ///////////////////////////////////////////////////////////////////////////
	public ref class TransportKeyWrap abstract : CAPI::TransportKeyWrap
    {
		// ����������������� ��������� � ��������
		private: CAPI::CSP::Provider^ provider; private: ContextHandle^ hContext; private: DWORD flags;

        // �����������
        protected: TransportKeyWrap(CAPI::CSP::Provider^ provider, ContextHandle^ hContext, DWORD flags) 
        {     
            // ��������� ���������� ���������
            this->provider = RefObject::AddRef(provider); 

            // ��������� ���������� ���������
			this->hContext = Handle::AddRef(hContext); this->flags = flags;
        } 
		// ����������
		public: virtual ~TransportKeyWrap() 
		{ 
			// ���������� ���������� �������
			Handle::Release(hContext); RefObject::Release(provider);  
		}
		// ����������������� ��������� � ��������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}

        // ����������� ����
        public: virtual TransportKeyData^ Wrap(
			ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
			IPublicKey^ publicKey, IRand^ rand, ISecretKey^ CEK) override;  

		// ������������ ��������� ���������
		protected: virtual ASN1::IEncodable^ EncodeParameters() = 0; 
    };
	public ref class TransportKeyUnwrap abstract : CAPI::TransportKeyUnwrap
    {
		// ����������������� ���������
		private: CAPI::CSP::Provider^ provider; private: DWORD flags;

        // �����������
        protected: TransportKeyUnwrap(CAPI::CSP::Provider^ provider, DWORD flags) 
        {     
            // ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); this->flags = flags;
        }
		// ����������
		public: virtual ~TransportKeyUnwrap() { RefObject::Release(provider);  }

		// ����������������� ���������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

        // ������������ ����
        public: virtual ISecretKey^ Unwrap(IPrivateKey^ privateKey, 
			TransportKeyData^ transportData, SecretKeyFactory^ keyFactory) override; 

		// ������������� ��������� �����
		protected: virtual ALG_ID GetPublicKeyID(IParameters^ parameters) = 0; 
	};
}
}}
