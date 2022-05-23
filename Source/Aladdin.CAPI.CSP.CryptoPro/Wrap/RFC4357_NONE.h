#pragma once
#include "RFC4357.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace Wrap
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ����� ���� 28147-89 ��� ��������������
	///////////////////////////////////////////////////////////////////////////
	public ref class RFC4357_NONE : RFC4357
	{
		// �����������
		public: RFC4357_NONE(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			
            // ��������� ���������� ���������
			String^ sboxOID, array<BYTE>^ ukm) : RFC4357(provider, hContext, sboxOID, ukm) {}

		// ������������� ��������� 
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_SIMPLE_EXPORT; } }

	    // �������� �������� �������������� �����
		public: virtual CAPI::KeyDerive^ GetKDFAlgorithm(CAPI::CSP::ContextHandle^ hContext) override 
		{ 
			// �������������� ����� �����������
			return gcnew CAPI::Derive::NOKDF(GOST::Engine::GOST28147::Endian); 
		}
    }; 
}}}}}
