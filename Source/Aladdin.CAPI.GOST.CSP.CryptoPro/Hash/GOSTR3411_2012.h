#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� ���� � 34.11-2012
	///////////////////////////////////////////////////////////////////////////
	public ref class GOSTR3411_2012 : CAPI::CSP::Hash
	{
		// �����������
		public: GOSTR3411_2012(CAPI::CSP::Provider^ provider, 
			CAPI::CSP::ContextHandle^ hContext, int bits) 

			// ��������� ���������� ���������
			: CAPI::CSP::Hash(provider, hContext) { this->bits = bits; } private: int bits; 

        // ������������� ���������
		public: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// ������� ������������� ���������
			return (bits == 256) ? CALG_GR3411_2012_256 : CALG_GR3411_2012_512; 
		}}
		// ������ ����� � ���-��������
		public: virtual property int BlockSize { int get() override { return 64;       }}
		public: virtual property int HashSize  { int get() override { return bits / 8; }}
	};
}}}}}}
