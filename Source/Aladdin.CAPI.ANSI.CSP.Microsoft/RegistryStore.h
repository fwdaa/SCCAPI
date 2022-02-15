#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// ��������� ����������� � �������
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CAPI::CSP::RegistryStore
	{
		// �����������
		public: RegistryStore(CAPI::CSP::Provider^ provider, CAPI::Scope scope) 

			// ��������� ���������� ���������
			: CAPI::CSP::RegistryStore(provider, scope, CAPI::CSP::Container::typeid, 0) {} 

		// �������� ���������� ��������� �����
		public protected: virtual Certificate^ GetCertificate(CAPI::CSP::KeyHandle^ hKeyPair, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo) override;  

		// ��������� ���������� ��������� �����
		public protected: virtual void SetCertificate(
			CAPI::CSP::KeyHandle^ hKeyPair, Certificate^ certificate) override; 
	}; 
}}}}}
