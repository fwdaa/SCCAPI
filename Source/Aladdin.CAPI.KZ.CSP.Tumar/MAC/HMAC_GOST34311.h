#pragma once
#include "..\Hash\GOST34311.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace MAC 
{
	///////////////////////////////////////////////////////////////////////////
	// �������� HMAC ���� � 34.11-1994
	///////////////////////////////////////////////////////////////////////////
	public ref class HMAC_GOST34311 : CAPI::CSP::Mac
	{
		// ������������� ��������� � �������� HMAC
		private: ALG_ID algID; private: Hash::GOST34311 hash; Using<CAPI::Mac^> hMAC;

		// �����������
		public: HMAC_GOST34311(CAPI::CSP::Provider^ provider, 
			CAPI::CSP::ContextHandle^ hContext, ALG_ID algID) 

			// ��������� ���������� ���������
			: CAPI::CSP::Mac(provider, hContext, 0), 

			// ������� �������� �����������
			hash(provider, hContext, (algID == CALG_TGR3411_HMAC) ? CALG_TGR3411 : CALG_CPGR3411)
		{ 
			// ��������� ���������� ���������
			this->algID = algID; 
		} 
		// ����������
		public: virtual ~HMAC_GOST34311() {}

        // ������������� ���������
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return algID; }}

		// ������ ������������
		public:	virtual property int MacSize { int get() override { return 32; }}   
		// ������ �����
		public:	virtual property int BlockSize { int get() override { return hash.BlockSize; }}   

		// ���������������� ��������
		public: virtual void Init(ISecretKey^ key) override; 
		// ������������ ������
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override
		{
			// ������� ������� �������
			if (hMAC.Get() == nullptr) CAPI::CSP::Mac::Update(data, dataOff, dataLen);  

			// ������������ ������
			else hMAC.Get()->Update(data, dataOff, dataLen); return;  
		}
		// �������� ������������
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override
		{
			// ������� ������� �������
			if (hMAC.Get() == nullptr) return CAPI::CSP::Mac::Finish(buffer, bufferOff); 

			// �������� ������������
			int length = hMAC.Get()->Finish(buffer, bufferOff); 

			// ���������� ���������� �������
			hMAC.Close(); return length; 
		}
	}; 
}}}}}}