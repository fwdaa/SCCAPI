#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class VerifyHash : Microsoft::Sign::RSA::VerifyHash
	{
		// �����������
		public: VerifyHash(CAPI::CSP::Provider^ provider) 
			
			// ��������� ���������� ���������
			: Microsoft::Sign::RSA::VerifyHash(provider) {} 
	};
}}}}}}
