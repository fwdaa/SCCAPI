#pragma once
#include "..\..\Hash\GOSTR3411_1994.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Sign { namespace GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // ������� ������ ���� � 34.10-2001
    ///////////////////////////////////////////////////////////////////////////
	public ref class VerifyData2001 : GOST::Sign::GOSTR3410::VerifyData2001
	{
		// ������������ ���������
		private: CAPI::CSP::Provider^ provider; 

	    // �����������
		public: VerifyData2001(CAPI::CSP::Provider^ provider, CAPI::VerifyHash^ signAlgorithm) 
			
			// ��������� ���������� ���������
			: GOST::Sign::GOSTR3410::VerifyData2001(signAlgorithm) 
		{
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); 
		}
		// ����������
		public: virtual ~VerifyData2001() { RefObject::Release(provider); }

		// �������� �������� �����������
		protected: virtual CAPI::Hash^ CreateHashAlgorithm(String^ hashOID) override
		{
			// ������� �������� �����������
			return gcnew Hash::GOSTR3411_1994(provider, provider->Handle, hashOID); 
		}
	}; 
}}}}}}}
