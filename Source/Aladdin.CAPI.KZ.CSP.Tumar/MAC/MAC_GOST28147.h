#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ������������ ���� 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST28147 : CAPI::CSP::Mac
	{
		// �����������
		public: GOST28147(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			
			// ��������� ���������� ���������
			String^ sboxOID) : CAPI::CSP::Mac(provider, hContext, 0) 
		
			// ��������� ���������� ���������
			{ this->sboxOID = sboxOID; } private: String^ sboxOID;

        // ������������� ���������
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_GOST_IMIT; }}

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return GOST::Keys::GOST28147::Instance; }
		}
		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes 
		{ 
			// ������ ����� � ������
			array<int>^ get() override { return gcnew array<int> {32}; }
		}
		// ������ ������������
		public: virtual property int MacSize { int get() override { return 8;  }}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8;  }}

		// ���������� ��������� ��������� ����������
		protected: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override; 
	};
}}}}}}

