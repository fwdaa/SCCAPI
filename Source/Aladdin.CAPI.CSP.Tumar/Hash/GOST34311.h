#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� ���� � 34.11-1994
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST34311 : CAPI::CSP::Hash
	{
		// �����������
		public: GOST34311(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, ALG_ID algID) 

			// ��������� ���������� ���������
			: CAPI::CSP::Hash(provider, hContext) { this->algID = algID; } private: ALG_ID algID; 

        // ������������� ���������
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return algID; }}

		// ������ ����� � ���-��������
		public: virtual property int BlockSize { int get() override { return 32; }}
		public: virtual property int HashSize  { int get() override { return 32; }}
	};
}}}}}
