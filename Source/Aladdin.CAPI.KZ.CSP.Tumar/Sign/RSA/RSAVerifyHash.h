#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class VerifyHash : ANSI::CSP::Microsoft::Sign::RSA::VerifyHash
	{
		// �����������
		public: VerifyHash(CAPI::CSP::Provider^ provider) 
			
			// ��������� ���������� ���������
			: ANSI::CSP::Microsoft::Sign::RSA::VerifyHash(provider) {} 
	};
}}}}}}}
