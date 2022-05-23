#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ���� 
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::GOST::GOSTR3410::IECPrivateKey
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian;

		// �����������
		public: PrivateKey(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, GOST::GOSTR3410::IECPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID, DWORD keyType)

			// ��������� ���������� ���������
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, keyType) {} 

		// ��������� ��������
		public: virtual property Math::BigInteger^ D { Math::BigInteger^ get() 
		{ 
			// ������� ��������� �������� 
			return (d != nullptr) ? d : (GetPrivateValue(), d); 
		}}	
		// ���������� ��������� ��������
		private: void GetPrivateValue(); private: Math::BigInteger^ d;
	};
}}}}}
