#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// �����������
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, GOST::GOSTR3410::IECParameters^ parameters) 

			// ��������� ���������� ���������
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) 

			// ��������� ���������� ���������
			{ this->keyOID = keyOID; } private: String^ keyOID;
		
		// ������������� ���� ������
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
            String^ keyOID, DWORD keyType, DWORD keyFlags) override; 
	}; 
}}}}}}
