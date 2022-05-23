#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace X942
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ���� DH
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::ANSI::X942::IPrivateKey
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// �����������
		public: PrivateKey(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, CAPI::ANSI::X942::IPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID)

			// ��������� ���������� ���������
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, AT_KEYEXCHANGE) {} 

		// ��������� ��������
		public: virtual property Math::BigInteger^ X { Math::BigInteger^ get() 
		{ 
			// ������� ��������� �������� 
			return (x != nullptr) ? x : (GetPrivateValue(), x); 
		}}	
		// ���������� ��������� ��������
		private: void GetPrivateValue(); private: Math::BigInteger^ x;
	};
}}}}}
