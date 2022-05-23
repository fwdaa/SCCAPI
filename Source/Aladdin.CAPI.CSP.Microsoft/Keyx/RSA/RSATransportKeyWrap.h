#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Keyx { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // �������� ���������� �����
    ///////////////////////////////////////////////////////////////////////////
	public ref class TransportKeyWrap : CAPI::CSP::TransportKeyWrap
    {
        // �����������
        public: TransportKeyWrap(CAPI::CSP::Provider^ provider, DWORD flags) 

            // ��������� ���������� ���������
			: CAPI::CSP::TransportKeyWrap(provider, provider->Handle, flags) 
		
			// ��������� ���������� ���������
			{ this->oaep = (flags & CRYPT_OAEP) != 0; } private: bool oaep;

        // ����������� ����
        public: virtual TransportKeyData^ Wrap(
			ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
			IPublicKey^ publicKey, IRand^ rand, ISecretKey^ CEK) override
		{
			// ����������� ����
			TransportKeyData^ transportData = 
				CAPI::CSP::TransportKeyWrap::Wrap(
					algorithmParameters, publicKey, rand, CEK
			); 
			// �������� ������� ���������� ������
			Array::Reverse(transportData->EncryptedKey); return transportData; 
		}
		// �������� ��������� ���������
		protected: virtual ASN1::IEncodable^ EncodeParameters() override
		{
			// ������� ��������� ���������
			if (!oaep) return ASN1::Null::Instance; 

			// ������� ��������� ���������
			return gcnew ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams(
				nullptr, nullptr, (ASN1::ISO::AlgorithmIdentifier^)nullptr
			); 
		}
    };
}}}}}}
