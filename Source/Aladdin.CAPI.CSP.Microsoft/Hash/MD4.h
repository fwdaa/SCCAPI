#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Hash 
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� MD4
	///////////////////////////////////////////////////////////////////////////
	public ref class MD4 : CAPI::CSP::Hash
	{
		// �����������
		public: MD4(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext)
			
			// ��������� ���������� ���������
			: CAPI::CSP::Hash(provider, hContext) {} 

        // ������������� ���������
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_MD4; }}

		// ������ ���-�������� � ����� � ������
		public: virtual property int HashSize  { int get() override { return 16; } }  
		public: virtual property int BlockSize { int get() override { return 64; } }   
	};
}}}}}
