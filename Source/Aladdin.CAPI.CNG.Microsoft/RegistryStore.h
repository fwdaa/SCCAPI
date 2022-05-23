#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// ��������� ����������� � �������
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CAPI::CNG::RegistryStore
	{
		// �����������
		public: RegistryStore(CAPI::CNG::NProvider^ provider, CAPI::Scope scope) 

			// ��������� ���������� ���������
            : CAPI::CNG::RegistryStore(provider, scope, 0) {} 

		// �������� ���������� ��������� �����
		public protected: virtual Certificate^ GetCertificate(
			CAPI::CNG::NKeyHandle^ hPrivateKey, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo) override;  

		// �������� ���� ������������
		public protected: virtual array<Certificate^>^ GetCertificateChain(
			Certificate^ certificate) override; 
		
		// ��������� ���������� ��������� �����
		public protected: virtual void SetCertificateChain(
			CAPI::CNG::NKeyHandle^ hPrivateKey, 
			array<Certificate^>^ certificateChain) override; 
	}; 
}}}}
