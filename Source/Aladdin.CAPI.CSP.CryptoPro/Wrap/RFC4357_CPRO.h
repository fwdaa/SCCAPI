#pragma once
#include "RFC4357.h"
#include "..\Cipher\GOST28147.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace Wrap
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ����� ���� 28147-89 c ���������������
	///////////////////////////////////////////////////////////////////////////
	public ref class RFC4357_CPRO : RFC4357
	{
		// �����������
		public: RFC4357_CPRO(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			
            // ��������� ���������� ���������
			String^ sboxOID, array<BYTE>^ ukm) : RFC4357(provider, hContext, sboxOID, ukm) {}

		// ������������� ��������� 
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_PRO_EXPORT; } }

	    // �������� �������� �������������� �����
		public: virtual CAPI::KeyDerive^ GetKDFAlgorithm(CAPI::CSP::ContextHandle^ hContext) override
        {
			// ������� ������� �������� ����������
			Using<IBlockCipher^> blockCipher(gcnew Cipher::GOST28147(
				Provider, hContext, SBoxOID, ASN1::GOST::OID::keyMeshing_none
			)); 
            // ������� �������� �������������� �����
            return gcnew CAPI::GOST::Derive::RFC4357(blockCipher.Get()); 
        } 
	};
}}}}}
