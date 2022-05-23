#pragma once
#include "..\Hash\GOSTR3411_1994.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// �������� HMAC ���� � 34.11-1994
	///////////////////////////////////////////////////////////////////////////
	public ref class HMAC_GOSTR3411_1994 : CAPI::CSP::Mac
	{
		// ������������� ���������� � �������� HMAC
		private: String^ paramsOID; private: Hash::GOSTR3411_1994 hash; Using<CAPI::Mac^> hMAC; 

		// �����������
		public: HMAC_GOSTR3411_1994(CAPI::CSP::Provider^ provider, 
			CAPI::CSP::ContextHandle^ hContext, String^ paramsOID) 

			// ��������� ���������� ���������
			: CAPI::CSP::Mac(provider, hContext, 0), hash(provider, hContext, paramsOID)
		{ 
			// ��������� ���������� ���������
			this->paramsOID = paramsOID; 
		} 
		// ����������
		public: virtual ~HMAC_GOSTR3411_1994() {}

        // ������������� ���������
		protected: virtual property ALG_ID AlgID 
		{ 
			// ������������� ���������
			ALG_ID get() override { return CALG_GR3411_HMAC; }
		}
		// ������ ������������
		public:	virtual property int MacSize { int get() override { return 32; }}  
		// ������ ������������
		public:	virtual property int BlockSize { int get() override { return hash.BlockSize; }}  

		// ���������������� ��������
		public: virtual void Init(ISecretKey^ key) override; 
		// ������������ ������
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override
		{
			// ������� ������� �������
			if (hMAC.Get() == nullptr) CAPI::CSP::Mac::Update(data, dataOff, dataLen); 

			// ������������ ������
			else hMAC.Get()->Update(data, dataOff, dataLen);
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
}}}}}
