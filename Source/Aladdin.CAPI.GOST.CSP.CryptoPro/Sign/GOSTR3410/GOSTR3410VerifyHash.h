#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Sign { namespace GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� ���� � 34.10-2001, 2012
    ///////////////////////////////////////////////////////////////////////
    public ref class VerifyHash : CAPI::CSP::VerifyHash
	{
		// �����������
		public: VerifyHash(CAPI::CSP::Provider^ provider, ALG_ID hashID) 
			
			: CAPI::CSP::VerifyHash(provider, 0)
		 
			// ��������� ���������� ���������
			{ this->hashID = hashID; } private: ALG_ID hashID;
		 
		// ������� �������� �����������
		protected: virtual CAPI::CSP::HashHandle^ CreateHash(
			CAPI::CSP::ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm) override;

		// ��������� ������� ���-��������
		public: virtual void Verify(IPublicKey^ publicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
			array<BYTE>^ hash, array<BYTE>^ signature) override
		{
			// ������� ����� ������� � �������� ������� ������ 
			signature = (array<BYTE>^)signature->Clone(); Array::Reverse(signature);

			// ��������� ������� ���-��������
			return CAPI::CSP::VerifyHash::Verify(publicKey, hashAlgorithm, hash, signature); 
		}
	};
}}}}}}}