#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Keyx { namespace GOST34310
{
    ///////////////////////////////////////////////////////////////////////////
    // �������� ���������� �����
    ///////////////////////////////////////////////////////////////////////////
	public ref class TransportKeyWrap : CAPI::CSP::TransportKeyWrap
    {
        // �����������
		public: TransportKeyWrap(CAPI::CSP::Provider^ provider, DWORD flags) 

            // ��������� ���������� ���������
			: CAPI::CSP::TransportKeyWrap(provider, provider->Handle, flags) {}

        // ����������� ����
        public: virtual TransportKeyData^ Wrap(
			ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
			IPublicKey^ publicKey, IRand^ rand, ISecretKey^ CEK) override;  

		// �������� ��������� ���������
		protected: virtual ASN1::IEncodable^ EncodeParameters() override
		{
			// ������� ��������� ���������
			return ASN1::Null::Instance; 
		}
	};
}}}}}}}
