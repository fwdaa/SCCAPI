#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ������������ ���� 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST28147 : CAPI::CSP::Mac
	{
		private: String^		sboxOID;	// ������������� ������� �����������
		private: String^ 		meshing;	// ����� ����� �����
		private: array<BYTE>^	start;		// ��������� �������� 

		// �����������
		public: GOST28147(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 

			// ��������� ���������� ���������
			String^ sboxOID, String^ meshing, array<BYTE>^ start) : CAPI::CSP::Mac(provider, hContext, 0) 
		{
			this->sboxOID	= sboxOID;	// ������������� ������� �����������
			this->meshing	= meshing;	// ����� ����� �����
			this->start		= start;	// ��������� �������� 
		}
        // ������������� ���������
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_G28147_MAC; }}

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return GOST::Keys::GOST::Instance; }
		}
		// ������ ������������
		public: virtual property int MacSize { int get() override { return 4;  }}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8;  }}

		// ���������� ��������� ��������� ����������
		protected: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override; 

		// ������� �������� �����������
		protected: virtual CAPI::CSP::HashHandle^ Construct(
			CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) override; 
	}; 
}}}}}
