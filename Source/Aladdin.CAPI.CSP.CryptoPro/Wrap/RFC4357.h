#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace Wrap
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ����� ���� 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class RFC4357 abstract : CAPI::CSP::KeyWrap
	{
		// ������������� ������� ����������� � ��������� ������    
		private: String^ sboxOID; private: array<BYTE>^ ukm; 

		// �����������
		protected: RFC4357(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			
            // ��������� ���������� ���������
			String^ sboxOID, array<BYTE>^ ukm) : CAPI::CSP::KeyWrap(provider, hContext)
		{
            // ��������� ���������� ���������
			this->sboxOID = sboxOID; this->ukm = ukm;
		}
		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return GOST::Keys::GOST::Instance; }
		}
	    // �������� �������� �������������� �����
		public: virtual CAPI::KeyDerive^ GetKDFAlgorithm(CAPI::CSP::ContextHandle^ hContext) = 0; 

		// ����������� ����
		public: virtual array<BYTE>^ Wrap(IRand^ rand, ISecretKey^ key, ISecretKey^ CEK) override; 
		// ������������ ����
		public: virtual ISecretKey^ Unwrap(ISecretKey^ key, 
			array<BYTE>^ wrappedCEK, SecretKeyFactory^ keyFactory) override; 

		// ������������� ��������� 
		protected: virtual property ALG_ID  AlgID { ALG_ID  get() = 0; }

        // ������������� ������� �����������
		protected: virtual property String^ SBoxOID { String^ get() { return sboxOID; } }

		///////////////////////////////////////////////////////////////////////
		// ��������������� �������
		///////////////////////////////////////////////////////////////////////
		internal: static array<BYTE>^ WrapKey(ALG_ID algID, array<BYTE>^ ukm, 
			CAPI::CSP::KeyHandle^ hKEK, CAPI::CSP::KeyHandle^ hCEK
		); 
		internal: static CAPI::CSP::KeyHandle^ UnwrapKey(
			CAPI::CSP::ContextHandle^ hContext, ALG_ID algID, 
			array<BYTE>^ ukm, CAPI::CSP::KeyHandle^ hKEK, array<BYTE>^ wrappedCEK
		); 
	};
}}}}}
