#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Sign { namespace GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� ���� � 34.10-2001, 2012
    ///////////////////////////////////////////////////////////////////////
    public ref class SignHash : CAPI::CSP::SignHash
	{
		// �����������
		public: SignHash(CAPI::CSP::Provider^ provider, ALG_ID hashID) 
			
			// ��������� ���������� ���������
			: CAPI::CSP::SignHash(provider, 0) { this->hashID = hashID; } private: ALG_ID hashID;

		// ������� �������� �����������
		protected: virtual CAPI::CSP::HashHandle^ CreateHash(
			CAPI::CSP::ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm) override;

		// ��������� ���-��������
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override
		{
			// ��������� ���-��������
			array<BYTE>^ signature = CAPI::CSP::SignHash::Sign(
				privateKey, rand, hashAlgorithm, hash
			); 
			// �������� ������� ������
			Array::Reverse(signature); return signature; 
		}
	};
}}}}}}}
