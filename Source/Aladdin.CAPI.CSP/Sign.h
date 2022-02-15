#pragma once
#include "Provider.h"
#include "Key.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ������� ���-��������
	///////////////////////////////////////////////////////////////////////////
	public ref class SignHash abstract : CAPI::SignHash
	{
		// ������������ ���������
		private: CSP::Provider^ provider; DWORD flags; 

		// �����������
		protected: SignHash(CSP::Provider^ provider, DWORD flags) 
		{ 		   
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); this->flags = flags; 
		} 
		// ����������
		public: virtual ~SignHash() { RefObject::Release(provider); }

        // ����������������� ���������
		protected: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// ������� �������� �����������
		protected: virtual HashHandle^ CreateHash(ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ parameters) = 0; 

		// �������� ������� ���-��������
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� �������� ������� ���-��������
	///////////////////////////////////////////////////////////////////////////
	public ref class VerifyHash abstract : CAPI::VerifyHash
	{
		// ������������ ���������
		private: CSP::Provider^ provider; DWORD flags; 

		// �����������
		protected: VerifyHash(CSP::Provider^ provider, DWORD flags) 
		{ 
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); this->flags = flags;
		} 
		// ����������
		public: virtual ~VerifyHash() { RefObject::Release(provider); }

        // ����������������� ���������
		protected: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// ������� �������� �����������
		protected: virtual HashHandle^ CreateHash(ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ parameters) = 0; 

		// �������� �������� ������� ���-��������
		public: virtual void Verify(IPublicKey^ publicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
			array<BYTE>^ hash, array<BYTE>^ signature) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class SignData abstract : CAPI::SignData
	{
		private: CSP::Provider^		provider;	// ����������������� ��������� 
		private: DWORD				flags;		// ����� ����������
		private: Using<HashHandle^>	hHash;		// �������� �����������

		// �����������
		protected: SignData(Provider^ provider, DWORD flags) 
		{ 
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); this->flags = flags;
		}
		// ����������
		public: virtual ~SignData() { RefObject::Release(provider); } 

        // ����������������� ���������
		protected: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// ������� �������� �����������
		protected: virtual HashHandle^ CreateHash(
			ContextHandle^ hContext, IParameters^ parameters) = 0; 

		// ���������������� ��������
		public: virtual void Init(IPrivateKey^ privateKey, IRand^ rand) override; 
		// ���������� ������
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override;
		// �������� ������� ������
        public: virtual array<BYTE>^ Finish(IRand^ rand) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� �������� ������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class VerifyData abstract : CAPI::VerifyData
	{
		private: CSP::Provider^		provider;	// ����������������� ��������� 
		private: DWORD				flags;		// ����� ����������
		private: Using<HashHandle^>	hHash;		// �������� �����������

		// �����������
		protected: VerifyData(Provider^ provider, DWORD flags) 
		{ 
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); this->flags = flags;
		}
		// ����������
		public: virtual ~VerifyData() { RefObject::Release(provider); } 

        // ����������������� ���������
		protected: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// ������� �������� �����������
		protected: virtual HashHandle^ CreateHash(
			ContextHandle^ hContext, IParameters^ parameters) = 0; 

		// ���������������� ��������
		public: virtual void Init(IPublicKey^ publicKey, array<BYTE>^ signature) override; 
		// ���������� ������
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override;
		// ��������� ������� ������
		public: virtual void Finish() override;
	};
}}}