#pragma once
#include "SCardStores.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Tumar CSP
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : ANSI::CSP::Microsoft::RSA::AESEnhancedProvider
	{
		// �����������
		protected: Provider(DWORD type, String^ name, bool sspi) 
			
			// ��������� ���������� ���������
			: ANSI::CSP::Microsoft::RSA::AESEnhancedProvider(type, name, sspi, false) {}

		// ��� ������ �����������
		public: virtual property String^ Group { String^ get() override { return GT_TUMAR_PROV; }}

		// ��� ����������
		public: virtual property String^ Name 
		{ 
			// ��� ����������
			String^ get() override { return CAPI::CSP::Provider::Name; }
		}
		// �������� ��������� ����������
		public: virtual array<String^>^ EnumerateStores(Scope scope) override 
		{ 
			// ������� ������ ��������
			return gcnew array<String^> { "Card" }; 
		}
		// �������� ��������� ����������
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// ������� ��������� �����������
			return gcnew SCardStores(this, scope); 
		}
		// �������������� ������� ����������� ������
		public: virtual array<SecretKeyFactory^>^ SecretKeyFactories() override
		{
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew KZ::Factory()); 

			// �������������� ������� ����������� ������
			return factory.Get()->SecretKeyFactories(); 
		}
	    // �������������� ������� ����������� ������
		public: virtual array<KeyFactory^>^ KeyFactories() override
		{
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew KZ::Factory()); 

			// �������������� ������� ����������� ������
			return factory.Get()->KeyFactories(); 
		}
		// �������� ��������� �� ���������
		public: virtual CAPI::Culture^ GetCulture(SecurityStore^ scope, String^ keyOID) override
        {
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew KZ::Factory()); 

			// �������� ��������� �� ���������
			return factory.Get()->GetCulture(scope, keyOID); 
		}
		// �������� ��������� �� ���������
		public: virtual PBE::PBECulture^ GetCulture(PBE::PBEParameters^ parameters, String^ keyOID) override
        {
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew KZ::Factory()); 

			// �������� ��������� �� ���������
			return factory.Get()->GetCulture(parameters, keyOID); 
		}
		// ������� �������� ��������� ������
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			String^ keyOID, IParameters^ parameters, IRand^ rand) override; 

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			CAPI::Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;

		// �������� ��� �����
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override; 

		///////////////////////////////////////////////////////////////////////
		// ���������� �������� � ��������/������ ������ ����������
		///////////////////////////////////////////////////////////////////////

		// ������������� ������������� �����
		public: virtual String^ ConvertKeyOID(ALG_ID keyID) override; 

		// ������������� ������������� �����
		public: virtual ALG_ID ConvertKeyOID(String^ keyID, DWORD keyType) override; 

		// ������������� �������� ����
		public: virtual CAPI::CSP::KeyHandle^ ImportPublicKey(
			CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType) override;
 
		// �������������� �������� ����
		public: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
			ExportPublicKey(CAPI::CSP::KeyHandle^ hPublicKey) override;

		// ������������� ���� ������
		public protected: virtual CAPI::CSP::KeyHandle^ ImportKeyPair(
			CAPI::CSP::Container^ container, DWORD keyType, 
			DWORD keyFlags, IPublicKey^ publicKey, IPrivateKey^ privateKey) override; 

		// �������� ������ ����
		public protected: virtual CAPI::CSP::PrivateKey^ GetPrivateKey(
			SecurityObject^ scope, IPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType) override; 
	};
}}}}}
