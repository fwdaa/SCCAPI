#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Keyx { namespace GOST34310
{
    ///////////////////////////////////////////////////////////////////////////
    // �������� ���������� �����
    ///////////////////////////////////////////////////////////////////////////
    public ref class TransportKeyUnwrap : CAPI::CSP::TransportKeyUnwrap
    {
        // �����������
        public: TransportKeyUnwrap(CAPI::CSP::Provider^ provider, DWORD flags) 

            // ��������� ���������� ���������
			: CAPI::CSP::TransportKeyUnwrap(provider, flags) {}

        // ������������ ����
        public: virtual ISecretKey^ Unwrap(IPrivateKey^ privateKey, 
			TransportKeyData^ transportData, SecretKeyFactory^ keyFactory) override; 

		// ������������� ��������� �����
		protected: virtual ALG_ID GetPublicKeyID(IParameters^ parameters) override { return CALG_ELGAM; }	
    };
}}}}}}}

