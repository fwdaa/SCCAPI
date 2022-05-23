#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA
    ///////////////////////////////////////////////////////////////////////
    public ref class VerifyHash : CAPI::CSP::VerifyHash
	{
		// �����������
		public: VerifyHash(CAPI::CSP::Provider^ provider) : CAPI::CSP::VerifyHash(provider, 0) {} 

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
}}}}}}
