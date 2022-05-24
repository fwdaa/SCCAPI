#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// ��������� ����������� � �������
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CSP::RegistryStore
	{
		// �����������
		public: RegistryStore(CSP::Provider^ provider, CAPI::Scope scope) 

			// ��������� ���������� ���������
			: CSP::RegistryStore(provider, scope, CSP::Container::typeid, 0) {} 

		// �������� ���������� ��������� �����
		public protected: virtual Certificate^ GetCertificate(
			CAPI::CSP::KeyHandle^ hKeyPair, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo) override;  

		// ��������� ���� ������������
		public protected: virtual void SetCertificateChain(
			CAPI::CSP::KeyHandle^ hKeyPair, 
			array<Certificate^>^ certificateChain) override; 
	}; 
}}}}
