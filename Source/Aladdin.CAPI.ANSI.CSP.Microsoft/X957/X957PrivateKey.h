#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace X957
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ���� DSA
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::ANSI::X957::IPrivateKey
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// �����������
		public: PrivateKey(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, CAPI::ANSI::X957::IPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID)

			// ��������� ���������� ���������
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, AT_SIGNATURE) {} 

		// ��������� ��������
		public: virtual property Math::BigInteger^ X { Math::BigInteger^ get() 
		{ 
			// ������� ��������� �������� 
			return (x != nullptr) ? x : (GetPrivateValue(), x); 
		}}	
		// ���������� ��������� ��������
		private: void GetPrivateValue(); private: Math::BigInteger^ x;
	};
}}}}}}
