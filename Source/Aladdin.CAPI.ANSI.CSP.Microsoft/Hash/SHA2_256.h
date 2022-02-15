#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Hash 
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� SHA-256
	///////////////////////////////////////////////////////////////////////////
	public ref class SHA2_256 : CAPI::CSP::Hash
	{
		// �����������
		public: SHA2_256(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext)
			
			// ��������� ���������� ���������
			: CAPI::CSP::Hash(provider, hContext) {} 

        // ������������� ���������
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_SHA_256; }}

		// ������ ���-�������� � ����� � ������
		public: virtual property int HashSize  { int get() override { return 32; } }  
		public: virtual property int BlockSize { int get() override { return 64; } }   
	};
}}}}}}

