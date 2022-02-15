#pragma once

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP { namespace BelT
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� BELT
	///////////////////////////////////////////////////////////////////////////
	public ref class Hash : CAPI::CSP::Hash
	{
		// �����������
		public: Hash(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle hContext) 

			// ��������� ���������� ���������
			: CAPI::CSP::Hash(provider, hContext) {}

        // ������������� ���������
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_BELT_HASH; }}

		// ������ ����� � ���-��������
		public: virtual property int BlockSize { int get() override { return 32; } }
		public: virtual property int HashSize  { int get() override { return 32; } }

		// ������� �������� �����������
		public protected: virtual CAPI::CSP::HashHandle Construct() override
		{
			// ������� �������� �����������
			return CAPI::CSP::Hash::Construct(); 
		} 
	};
}}}}}}