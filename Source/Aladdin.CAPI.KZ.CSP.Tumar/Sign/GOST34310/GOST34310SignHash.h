#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Sign { namespace GOST34310
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� ���� � 34.10-2001
    ///////////////////////////////////////////////////////////////////////
    public ref class SignHash : CAPI::CSP::SignHash
	{
		// �����������
		public: SignHash(CAPI::CSP::Provider^ provider, ALG_ID hashID) 
			
			// ��������� ���������� ���������
			: CAPI::CSP::SignHash(provider, 0) 
		
			// ��������� ���������� ���������
			{ this->hashID = hashID; } private: ALG_ID hashID;

		// ��������� ���-��������
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;

		// ������� �������� �����������
		protected: virtual CAPI::CSP::HashHandle^ CreateHash(
			CAPI::CSP::ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm) override;
	};
}}}}}}}
