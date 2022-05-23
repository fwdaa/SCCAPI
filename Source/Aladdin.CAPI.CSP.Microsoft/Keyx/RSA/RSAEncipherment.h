#pragma once
#include "RSATransportKeyWrap.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Keyx { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� ���������� ������ RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class Encipherment : CAPI::CSP::Encipherment
	{
		// ��������� ���������
		private: Using<TransportKeyWrap^> wrapAlgorithm; 

		// �����������
		public: Encipherment(CAPI::CSP::Provider^ provider, DWORD flags) 
			
			// ��������� ���������� ���������
			: CAPI::CSP::Encipherment(provider, flags), 

			// ������� �������� ���������� �����
			wrapAlgorithm(gcnew RSA::TransportKeyWrap(provider, flags)) {}

		// ����������� ������
		public: virtual array<BYTE>^ Encrypt(IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data) override
		{
			// ����������� ������
			array<BYTE>^ encrypted = CAPI::CSP::Encipherment::Encrypt(publicKey, rand, data); 

			// �������� ������� ������
			Array::Reverse(encrypted); return encrypted; 
		}
	    // ����������� ����
		public: virtual TransportKeyData^ Wrap(
			ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
			IPublicKey^ publicKey, IRand^ rand, ISecretKey^ key) override
        {
            // ��������� ��� �����
            if (key->Value == nullptr) return wrapAlgorithm.Get()->Wrap(
				algorithmParameters, publicKey, rand, key
			);  
			// ������� ������� �������
			return CAPI::CSP::Encipherment::Wrap(algorithmParameters, publicKey, rand, key); 
        }
	};
}}}}}}
