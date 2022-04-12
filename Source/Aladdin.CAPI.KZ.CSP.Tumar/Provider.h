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
			: ANSI::CSP::Microsoft::RSA::AESEnhancedProvider(type, name, sspi, false) 
		{
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew KZ::Factory()); 

			// ��� ���� ������ ����������
			for each (KeyValuePair<String^, CAPI::KeyFactory^> item in factory.Get()->KeyFactories())
			{
				// �������� ������� ����������
				KeyFactories()->Add(item.Key, item.Value); 
			}
		}
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
		// ������� �������� ��������� ������
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			CAPI::Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;

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
