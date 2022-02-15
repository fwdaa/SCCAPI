#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA
    ///////////////////////////////////////////////////////////////////////
    public ref class SignHash : CAPI::CSP::SignHash
	{
		// �����������
		public: SignHash(CAPI::CSP::Provider^ provider) : CAPI::CSP::SignHash(provider, 0) {} 

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
