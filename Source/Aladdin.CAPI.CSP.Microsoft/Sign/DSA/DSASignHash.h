#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Sign { namespace DSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� DH
    ///////////////////////////////////////////////////////////////////////
    public ref class SignHash : CAPI::CSP::SignHash
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// �����������
		public: SignHash(CAPI::CSP::Provider^ provider) : CAPI::CSP::SignHash(provider, 0) {} 

		// ������� �������� �����������
		protected: virtual CAPI::CSP::HashHandle^ CreateHash(
			CAPI::CSP::ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm) override;

		// ��������� ���-��������
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;
	};
}}}}}}
