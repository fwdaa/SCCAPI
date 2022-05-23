#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Keyx { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // �������� ���������� �����
    ///////////////////////////////////////////////////////////////////////////
    public ref class TransportKeyUnwrap : CAPI::CSP::TransportKeyUnwrap
    {
        // �����������
        public: TransportKeyUnwrap(CAPI::CSP::Provider^ provider, DWORD flags) 

            // ��������� ���������� ���������
			: CAPI::CSP::TransportKeyUnwrap(provider, flags | CRYPT_IPSEC_HMAC_KEY) {}

        // ������������ ����
        public: virtual ISecretKey^ Unwrap(IPrivateKey^ privateKey, 
			TransportKeyData^ transportData, SecretKeyFactory^ keyFactory) override
		{
			// ��������� ������� ����������
			if (transportData == nullptr) throw gcnew ArgumentException(); 

			// ����������� ������������� ����
			array<BYTE>^ encryptedKey = (array<BYTE>^)transportData->EncryptedKey->Clone(); 

			// �������� ������� ���������� ������
			Array::Reverse(encryptedKey); transportData = gcnew TransportKeyData(
				transportData->Algorithm, encryptedKey
			); 
			// ������������ ����
			return CAPI::CSP::TransportKeyUnwrap::Unwrap(privateKey, transportData, keyFactory); 
		}
		// ������������� ��������� �����
		protected: virtual ALG_ID GetPublicKeyID(IParameters^ parameters) override { return CALG_RSA_KEYX; }
    };
}}}}}}
