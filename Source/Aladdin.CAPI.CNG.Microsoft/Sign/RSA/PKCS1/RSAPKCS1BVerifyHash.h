#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BVerifyHash : CAPI::CNG::BVerifyHash
	{
		// �����������
		public: BVerifyHash(String^ provider) : CAPI::CNG::BVerifyHash(provider) {}
		 
		// ������� ��� ���������
		protected: virtual String^ GetName(IParameters^ parameters) override { return BCRYPT_RSA_ALGORITHM; }

		// ������������� �������� ����
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPublicKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) override; 

		// �������� �������� ������� ���-��������
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
}}}}}}}
