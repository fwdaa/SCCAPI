#pragma once
#include "RFC4357.h"
#include "..\MAC\HMAC_GOSTR3411_2012.h"


namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Wrap
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ����� ���� 28147-89 c ���������������
	///////////////////////////////////////////////////////////////////////////
	public ref class RFC4357_TC26 : RFC4357
	{
		// �����������
		public: RFC4357_TC26(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			String^ sboxOID, array<BYTE>^ ukm) 
			
            // ��������� ���������� ���������
			: RFC4357(provider, hContext, sboxOID, ukm) {}

		// ������������� ��������� 
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_PRO12_EXPORT; } }

	    // �������� �������� �������������� �����
        public: virtual KeyDerive^ GetKDFAlgorithm(CAPI::CSP::ContextHandle^ hContext) override
        {
            // ������� �������� ���������� ������������
            Using<CAPI::CSP::Mac^> hmac(gcnew MAC::HMAC_GOSTR3411_2012(Provider, hContext, 256)); 

            // ������� �������� label
            array<BYTE>^ label = gcnew array<BYTE> { 0x26, 0xBD, 0xB8, 0x78 }; 

            // ������� �������� �������������� �����
            return gcnew Derive::TC026(hmac.Get(), label);
        } 
	};
}}}}}}
