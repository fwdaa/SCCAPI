#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������������ HMAC
	///////////////////////////////////////////////////////////////////////////
	public ref class HMAC : CAPI::CSP::Mac
	{
		// ��������� ��������� �����������
		private: CAPI::CSP::Hash^ hashAlgorithm; 

		// �����������
		public: HMAC(CAPI::CSP::Provider^ provider, CAPI::CSP::Hash^ hashAlgorithm) 

			// ��������� ���������� ���������
			: CAPI::CSP::Mac(provider, provider->Handle, CRYPT_IPSEC_HMAC_KEY) 
        { 
			// ��������� ���������� ���������
            this->hashAlgorithm = RefObject::AddRef(hashAlgorithm); 
        }
        // ����������
		public: virtual ~HMAC() { RefObject::Release(hashAlgorithm); }
 
		// ������ ������������
		public:	virtual property int MacSize 
		{ 
			// ������ ������������
			int get() override { return hashAlgorithm->HashSize; }
		}  
		// ������ �����
		public:	virtual property int BlockSize 
		{ 
			// ������ �����
			int get() override { return hashAlgorithm->BlockSize; }
		}  
		// ������������� ���������
		protected: virtual property ALG_ID AlgID    
		{ 
			// ������������� ���������
			ALG_ID get() override { return CALG_HMAC; } 
		}
		// ������� �������� ���������� ������������
		protected: virtual CAPI::CSP::HashHandle^ Construct(
			CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) override; 
	};
}}}}}
