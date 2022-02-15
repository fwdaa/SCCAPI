#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	ref class BSign; ref class NSign; 

	///////////////////////////////////////////////////////////////////////////
	// �������� ������� ���-��������
	///////////////////////////////////////////////////////////////////////////
	public ref class BSignHash abstract : CAPI::SignHash
	{
		private: String^ provider;	// ��� ����������

		// �����������
		protected: BSignHash(String^ provider) { this->provider = provider; }
			
		// ��� ���������
		protected: virtual String^ GetName(IParameters^ parameters) = 0; 

		// ������������� ������ ����
		protected: virtual BKeyHandle^ ImportPrivateKey(
			BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) = 0; 

		// ��������� ���-��������
		protected: virtual array<BYTE>^ Sign(IParameters^ parameters, BKeyHandle^ hPrivateKey,  
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
		{
			// ��������� ���-��������
			return hPrivateKey->SignHash(IntPtr::Zero, hash, 0);
		}
		// �������� ������� ���-��������
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;
	};
	public ref class BVerifyHash abstract : CAPI::VerifyHash
	{
		private: String^ provider;	// ��� ����������

		// �����������
		protected: BVerifyHash(String^ provider) { this->provider = provider; }
			
		// ��� ���������
		protected: virtual String^ GetName(IParameters^ parameters) = 0; 

		// ������������� �������� ����
		protected: virtual BKeyHandle^ ImportPublicKey(
			BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) = 0; 

		// �������� �������� ������� ���-��������
		protected: virtual void Verify(IParameters^ parameters, BKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
		{
			// ��������� ������� ���-��������
			hPublicKey->VerifySignature(IntPtr::Zero, hash, signature, 0);   
		}
		// �������� �������� ������� ���-��������
		public: virtual void Verify(IPublicKey^ publicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
			array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
	public ref class NSignHash abstract : CAPI::SignHash
	{
		// ��������� ���-��������
		protected: array<BYTE>^ Sign(SecurityObject^ scope, 
			NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ hash, DWORD flags
		); 
		// ��������� ���-��������
		protected: virtual array<BYTE>^ Sign(SecurityObject^ scope, IParameters^ parameters, 
			NKeyHandle^ hPrivateKey, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
		{
			// ��������� ���-��������
			return Sign(scope, hPrivateKey, IntPtr::Zero, hash, 0);
		}
		// �������� ������� ���-��������
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;
	};
	public ref class NVerifyHash abstract : CAPI::VerifyHash
	{
		// �����������
		protected: NVerifyHash(NProvider^ provider) 
		
			// ��������� ���������� ���������
			{ this->provider = RefObject::AddRef(provider); } private: NProvider^ provider; 

		// ����������
		public: virtual ~NVerifyHash() { RefObject::Release(provider); }

		// �������� �������� ������� ���-��������
		protected: virtual void Verify(IParameters^ parameters, NKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
		{
			// ��������� ������� ���-��������
			hPublicKey->VerifySignature(IntPtr::Zero, hash, signature, 0);   
		}
		// �������� �������� ������� ���-��������
		public: virtual void Verify(IPublicKey^ publicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
			array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
}}}