#pragma once

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP { namespace GOST28147
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ����� ���� 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockEngine : CAPI::CSP::BlockEngine
	{
		// �����������
		public: BlockEngine(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext) 

            // ��������� ���������� ���������
            : CAPI::CSP::BlockEngine(provider, hContext) {} 

        // ������������� ��������� ����������
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_G28147; }}

		// ������ �����
		public: virtual property int BlockSize { int get() override { return  8; }}

		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes 
        { 
		    // ������ ����� � ������
            array<int>^ get() override { return gcnew array<int> { 32 }; } 
        }
	}; 
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ���� 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockCipher : CAPI::CSP::BlockCipher
	{
		private: String^ sboxOID;	// ������������� ������� �����������

		// �����������
		public: BlockCipher(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext, 
            String^ sboxOID, CipherMode mode, CAPI::PaddingMode padding, array<BYTE>^ iv) 
				: CAPI::CSP::BlockCipher(gcnew GOST28147::BlockEngine(provider, hContext), mode, padding, iv) 
		{
			this->sboxOID = sboxOID;	// ������������� ������� �����������
		} 
        // ������������� ��������� ����������
		public: virtual property ALG_ID AlgID { ALG_ID get() override 
        { 
            // ������������� ��������� ����������
            return (Padding == PaddingMode::PKCS7) ? CALG_G28147_PADDED : CALG_G28147; 
        }}
		// ���������� ��������� ��������� ����������
		public protected: virtual void SetParameters(CAPI::CSP::KeyHandle hKey) override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ������������ ���� 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class Imito : CAPI::CSP::Mac
	{
		private: String^ sboxOID;	// ������������� ������� �����������

		// �����������
		public: Imito(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext, 
            String^ sboxOID) : CAPI::CSP::Mac(provider, hContext) 
		{
			this->sboxOID = sboxOID;	// ������������� ������� �����������
		}
        // ������������� ����� ��������� 
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_G28147_MAC; }}
        // ������������� ����� ��������� 
		protected: virtual property ALG_ID KeyAlgID { ALG_ID get() override { return CALG_G28147; }}

		// ������ ������������
		public: virtual property int HashSize { int get() override { return 4;  }}

		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes 
        { 
		    // ������ ����� � ������
            array<int>^ get() override { return gcnew array<int> { 32 }; } 
        }
		// ���������� ��������� ��������� ����������
		public protected: virtual void SetParameters(CAPI::CSP::KeyHandle hKey) override; 
	}; 
}}}}}}
