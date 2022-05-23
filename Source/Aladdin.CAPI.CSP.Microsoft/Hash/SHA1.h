#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Hash 
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� SHA1
	///////////////////////////////////////////////////////////////////////////
	public ref class SHA1 : CAPI::CSP::Hash
	{
		// �����������
		public: SHA1(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext)
			
			// ��������� ���������� ���������
			: CAPI::CSP::Hash(provider, hContext) {} 

        // ������������� ���������
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_SHA1; }}

		// ������ ���-�������� � ����� � ������
		public: virtual property int HashSize  { int get() override { return 20; } }  
		public: virtual property int BlockSize { int get() override { return 64; } }   
	};
}}}}}
