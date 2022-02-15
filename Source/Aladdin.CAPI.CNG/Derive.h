#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ������������ ������ �����
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyAgreement abstract : CAPI::KeyAgreement
	{
		private: String^ provider;	// ��� ����������

		// �����������
		protected: BKeyAgreement(String^ provider) { this->provider = provider; }

	    // ����������� ����� ���� �� ������� ����������
		public: virtual ISecretKey^ DeriveKey(IPrivateKey^ privateKey, 
			IPublicKey^ publicKey, array<BYTE>^ random, 
			SecretKeyFactory^ keyFactory, int keySize) override; 

		// ��� ���������
		protected: virtual String^ GetName(IParameters^ parameters) = 0; 

		// ������������� ������ ����
		protected: virtual BKeyHandle^ ImportPrivateKey(
			BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) = 0; 

		// ������������� �������� ����
		protected: virtual BKeyHandle^ ImportPublicKey(
			BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) = 0; 

	    // ����������� ����� ���� �� ������� ����������
		protected: virtual array<BYTE>^ DeriveKey(IParameters^ parameters, 
			BSecretHandle^ hSecret, array<BYTE>^ random, int keySize) = 0; 

		// ��������� ������������ ������ �����
		protected: virtual BSecretHandle^ AgreementSecret(
			BKeyHandle^ hPrivateKey, BKeyHandle^ hPublicKey)
		{
			// ��������� ������������ ������ �����
			return hPrivateKey->AgreementSecret(hPublicKey, 0); 
		}
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� ������������ ������ �����
	///////////////////////////////////////////////////////////////////////////
	public ref class NKeyAgreement abstract : CAPI::KeyAgreement
	{
	    // ����������� ����� ���� �� ������� ����������
		public: virtual ISecretKey^ DeriveKey(IPrivateKey^ privateKey, 
			IPublicKey^ publicKey, array<BYTE>^ random, 
			SecretKeyFactory^ keyFactory, int keySize) override; 

		// ��������� ������������ ������ �����
		protected: NSecretHandle^ AgreementSecret(SecurityObject^ scope, 
			NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey, DWORD flags
		); 
		// ��������� ������������ ������ �����
		protected: virtual NSecretHandle^ AgreementSecret(
			SecurityObject^ scope, NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey)
		{
			// ��������� ������������ ������ �����
			return AgreementSecret(scope, hPrivateKey, hPublicKey, 0); 
		}
	    // ����������� ����� ���� �� ������� ����������
		protected: virtual array<BYTE>^ DeriveKey(IParameters^ parameters, 
			NSecretHandle^ hSecret, array<BYTE>^ random, int keySize) = 0; 
	};
}}}