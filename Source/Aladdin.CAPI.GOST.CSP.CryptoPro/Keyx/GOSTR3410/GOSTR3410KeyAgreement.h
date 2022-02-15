#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Keyx { namespace GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// ������������ ������ ����� ���� � 34.10-2001, 2012
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyAgreement : CAPI::CSP::KeyAgreement
	{
		// �����������
		public: KeyAgreement(CAPI::CSP::Provider^ provider, int sizeUKM) 
            : CAPI::CSP::KeyAgreement(provider, 0)
		 
            // ��������� ���������� ���������
			{ this->sizeUKM = sizeUKM; } private: int sizeUKM;

		// ������������� ��������� ������
		public: virtual array<BYTE>^ Generate(IParameters^ parameters, IRand^ rand) override
        {
            // �������� ������ ��� ��������� ������
            array<BYTE>^ random = gcnew array<BYTE>(sizeUKM); 

            // ������������� ��������� ������
            rand->Generate(random, 0, sizeUKM); return random; 
        } 
        // ���������� ��������� �����
        protected: virtual void SetKeyParameters(CAPI::CSP::ContextHandle^ hContext, 
            CAPI::CSP::KeyHandle^ hKey, array<BYTE>^ random, int keySize) override; 
	};
}}}}}}}
