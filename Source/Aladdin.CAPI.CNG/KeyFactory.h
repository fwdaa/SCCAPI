#pragma once

namespace Aladdin { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// ������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyFactory : CAPI::IKeyFactory
	{
		// ����������� ������� ������
		private: CAPI::IKeyFactory^ keyFactory; 

		// �����������
		public: KeyFactory(CAPI::IKeyFactory^ keyFactory)
		{
			// ��������� ���������� ���������
			this->keyFactory = keyFactory; 
		}
		// ������� ����������
		public: virtual property CAPI::IFactory2^ Factory 
		{ 
			// ������� ����������
			CAPI::IFactory2^ get() { return keyFactory->Factory; } 
		} 
		// ������������� �����
		public: virtual property String^ Oid 
		{ 
			// ������������� �����
			String^ get() { return keyFactory->Oid; } 
		} 
		// ��������� �����
		public: virtual property CAPI::IEncodedParameters^ Parameters 
		{ 
			// ��������� �����
			CAPI::IEncodedParameters^ get() { return keyFactory->Parameters; } 
		} 
		// ������������ �������� ����
		public: virtual ASN1::BitString^ EncodePublicKey(CAPI::IPublicKey^ publicKey)
		{
			// ������������ �������� ����
			return keyFactory->EncodePublicKey(publicKey); 
		}
		public: virtual ASN1::OctetString^ EncodePrivateKey(CAPI::IPrivateKey^ privateKey)
		{
			return nullptr; 
		}
		// ������������� ������� ����
		public: virtual CAPI::IPublicKey^ DecodePublicKey(ASN1::BitString^ encoded)
		{
			// ������������� ������� ����
			return keyFactory->DecodePublicKey(encoded); 
		}
		public: virtual CAPI::IPrivateKey^ DecodePrivateKey(ASN1::OctetString^ encoded)
		{
			return nullptr; 
		}
	}; 
}}
