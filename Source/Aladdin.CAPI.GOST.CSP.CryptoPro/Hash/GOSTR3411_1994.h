#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� ���� � 34.11-1994
	///////////////////////////////////////////////////////////////////////////
	public ref class GOSTR3411_1994 : CAPI::CSP::Hash
	{
		// ������������� ����������
		private: String^ paramsOID;

		// �����������
		public: GOSTR3411_1994(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, String^ paramsOID) 

			// ��������� ���������� ���������
			: CAPI::CSP::Hash(provider, hContext) { this->paramsOID = paramsOID; } 

        // ������������� ���������
		public: virtual property ALG_ID AlgID { ALG_ID get() override { return CALG_GR3411; }}

		// ������ ����� � ���-��������
		public: virtual property int BlockSize { int get() override { return 32; } }
		public: virtual property int HashSize  { int get() override { return 32; } }

		// ������� �������� �����������
		protected: virtual CAPI::CSP::HashHandle^ Construct() override; 
	};
}}}}}}
