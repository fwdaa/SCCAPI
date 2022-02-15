#pragma once

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP { namespace STB11761
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� ��� 1176.1
	///////////////////////////////////////////////////////////////////////////
	public ref class Hash : CAPI::CSP::Hash
	{
		private: array<BYTE>^ start; // ��������� ��������

		// �����������
		public: Hash(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext, array<BYTE>^ start) 

			// ���������� ��������� ��������
			: CAPI::CSP::Hash(provider, hContext) { this->start = start; }
			
        // ������������� ���������
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_BHF; }}

		// ������ ����� � ���-��������
		public: virtual property int BlockSize { int get() override { return 32; } }
		public: virtual property int HashSize  { int get() override { return 32; } }

		// ������� �������� �����������
		public protected: virtual CAPI::CSP::HashHandle Construct() override; 
	};
}}}}}}
