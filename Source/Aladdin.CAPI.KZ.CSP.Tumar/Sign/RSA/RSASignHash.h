#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class SignHash : ANSI::CSP::Microsoft::Sign::RSA::SignHash
	{
		// �����������
		public: SignHash(CAPI::CSP::Provider^ provider) 
			
			// ��������� ���������� ���������
			: ANSI::CSP::Microsoft::Sign::RSA::SignHash(provider) {} 

		// ��������� ���-��������
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;
	};
}}}}}}}

