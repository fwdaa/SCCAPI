#pragma once
#include "Provider.h"
#include "Cipher.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////
	// �������� ��������� ������������
	///////////////////////////////////////////////////////////////////////
	public ref class Mac abstract : CAPI::Mac
	{
        private: CSP::Provider^		provider;   // ����������������� ���������
		private: ContextHandle^		hContext;	// ����������������� ��������
		private: Using<KeyHandle^>	hKey;		// ���� ��� ���������� ������������ 
		private: Using<HashHandle^> hHash;		// �������� ���������� ������������ 
        private: DWORD				flags;      // �������������� ����� �������� �����
		
		// �����������
		protected: Mac(CSP::Provider^ provider, ContextHandle^ hContext, DWORD flags) 
		{ 
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); 
			
			// ��������� ���������� ���������
			this->hContext = Handle::AddRef(hContext); this->flags = flags; 	
		}
		// ����������
        public: virtual ~Mac() 
		{ 
			// ���������� ������������ �������
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// ����������������� ��������� � ��������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
    
		// ������������� ��������� �����������
		protected: virtual property ALG_ID AlgID { ALG_ID get() = 0; }

		// ���������� ��������� ���������
		protected: virtual void SetParameters(KeyHandle^ hKey) {} 

		// ������� �������� ���������� ������������
		protected: virtual HashHandle^ Construct(ContextHandle^ hContext, KeyHandle^ hKey)
		{
			// ������� �������� ���������� �����������
			return hContext->CreateHash(AlgID, hKey, 0); 
		} 
		// ���������������� ��������
		public: virtual void Init(ISecretKey^ key) override; 
		// ������������ ������
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override; 
		// �������� ������������
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override; 
	};
	///////////////////////////////////////////////////////////////////////
	// CBC-MAC
	///////////////////////////////////////////////////////////////////////
	public ref class CBC_MAC : Mac
	{
		// ������� �������� ���������� � ������ �������������
		private: BlockCipher^ blockCipher; private: array<BYTE>^ iv; 

		// �����������
		public: CBC_MAC(BlockCipher^ blockCipher, array<BYTE>^ iv) 
			
			// ��������� ���������� ���������
			: Mac(blockCipher->Provider, blockCipher->Context, 0)
		{ 
			// ��������� ���������� ���������
			this->blockCipher = RefObject::AddRef(blockCipher); this->iv = iv; 
		}
		// ����������
        public: virtual ~CBC_MAC() { RefObject::Release(blockCipher); }

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return blockCipher->KeyFactory; }
		}
		// ������ MAC-��������
		public: virtual property int MacSize 
		{ 
			// ������ MAC-��������
			int get() override { return blockCipher->BlockSize; }
		} 
		// ������ �����
		public: virtual property int BlockSize 
		{ 
			// ������ MAC-��������
			int get() override { return blockCipher->BlockSize; }
		} 
		// ������������� ���������
		protected: virtual property ALG_ID AlgID 
		{ 
			// ������������� ���������
			ALG_ID get() override { return CALG_MAC; }
		}
		// ���������� ��������� ���������
		protected: virtual void SetParameters(KeyHandle^ hKey) override 
		{
			// ���������� ��������� ���������
			blockCipher->SetParameters(hKey); 

			// ���������� ����� ���������� � �������������
			// hKey->SetLong(KP_MODE, CRYPT_MODE_CBC, 0); hKey->SetParam(KP_IV, iv, 0);

			// ������� ������ ����������
			// hKey->SetLong(KP_PADDING, PKCS5_PADDING, 0);
		} 
	}; 
}}}

