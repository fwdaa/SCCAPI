#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class Cipher abstract : CAPI::Cipher
	{
		// ����������������� ��������� � ��������
		private: CSP::Provider^ provider; private: ContextHandle^ hContext; 

		// �����������
		protected: Cipher(CSP::Provider^ provider, ContextHandle^ hContext) 
		{  
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); 
			
			// ��������� ���������� ���������
			this->hContext = Handle::AddRef(hContext); 
		} 
		// ����������
		public: virtual ~Cipher() 
		{ 
			// ���������� ���������� �������
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// ����������������� ��������� � ��������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
    
		// ���������� ��������� ���������
		public protected: virtual void SetParameters(KeyHandle^ hKey, PaddingMode padding) {} 

		// �������� ������������ ������
		protected: virtual Transform^ CreateEncryption(ISecretKey^ key) override; 
		// �������� ������������� ������
		protected: virtual Transform^ CreateDecryption(ISecretKey^ key) override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// ������� �������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockCipher abstract : RefObject, IBlockCipher
	{
		// ����������������� ��������� � ��������
		private: CSP::Provider^ provider; private: ContextHandle^ hContext; 

		// �����������
		protected: BlockCipher(CSP::Provider^ provider, ContextHandle^ hContext) 
		{  
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); 
			
			// ��������� ���������� ���������
			this->hContext = Handle::AddRef(hContext); 
		} 
		// ����������
		public: virtual ~BlockCipher() 
		{ 
			// ���������� ���������� �������
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// ����������������� ��������� � ��������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory { SecretKeyFactory^ get() = 0; }
		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes { array<int>^ get() = 0; }
		// ������ �����
		public: virtual property int BlockSize { int get()  = 0; }

		// ������� ����� ����������
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode); 

		// ���������� ��������� ���������
		public protected: virtual void SetParameters(KeyHandle^ hKey) {} 
	};
	///////////////////////////////////////////////////////////////////////////
	// ����� �������� ��������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockMode : Cipher
	{
		// ������� �������� ����������
		private: BlockCipher^ blockCipher; 
		// ����� ��������� � ������ ����������
		private: CipherMode^ mode; private: PaddingMode padding; 

		// �����������
		public: BlockMode(BlockCipher^ blockCipher, CipherMode^ mode, PaddingMode padding) 

			// ��������� ���������� ���������
			: Cipher(blockCipher->Provider, blockCipher->Context)
		{
			// ��������� ���������� ���������
			this->blockCipher = RefObject::AddRef(blockCipher); 

			// ��������� ���������� ���������
			this->mode = mode; this->padding = padding; 
		}
		// ����������
		public: virtual ~BlockMode() { RefObject::Release(blockCipher); }

        // ����� ���������
		public: virtual property CipherMode^ Mode { CipherMode^	get() override { return mode; }}	
		// ������ ����������
		public: property PaddingMode Padding { PaddingMode get() { return padding; }}	

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return blockCipher->KeyFactory; } 
		}
		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes 
		{ 
			// ������ ����� � ������
			array<int>^ get() override { return blockCipher->KeySizes; }
		}
		// ������ �����
		public: virtual property int BlockSize 
		{ 
			// ������ �����
			int get() override { return blockCipher->BlockSize; }
		}
		// �������� ������������ ������
		public: virtual Transform^ CreateEncryption(ISecretKey^ key, PaddingMode padding) override; 
		// �������� ������������� ������
		public: virtual Transform^ CreateDecryption(ISecretKey^ key, PaddingMode padding) override; 

		// �������� ������������ ������
		protected: virtual Transform^ CreateEncryption(ISecretKey^ key) override; 
		// �������� ������������� ������
		protected: virtual Transform^ CreateDecryption(ISecretKey^ key) override; 

		// ���������� ��������� ���������
		public protected: virtual void SetParameters(KeyHandle^ hKey, PaddingMode padding) override; 

        // ������� ����� ����������
		protected: virtual BlockPadding^ GetPadding();  
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� ������������
	///////////////////////////////////////////////////////////////////////////
	public ref class Encryption : Transform
	{
		private: Cipher^			cipher;		// �������� ����������
		private: PaddingMode		padding;	// ����� ����������
		private: ISecretKey^		key;		// �������� ����� ����������
		private: Using<KeyHandle^>	hKey;		// ��������� �����

		// �����������
		public: Encryption(Cipher^ cipher, PaddingMode padding, ISecretKey^ key) 
		{
			// ��������� ���������� ���������
            this->cipher = RefObject::AddRef(cipher); 
			
			// ��������� ���������� ���������
			this->padding = padding; this->key = RefObject::AddRef(key); 
		}
		// ����������
		public: virtual ~Encryption() 
		{ 
			// ���������� ���������� �������
			RefObject::Release(key); RefObject::Release(cipher); 
		}
		// ������ ����� ���������
		public: virtual property int BlockSize  { int get() override { return cipher->BlockSize; }}
		// ������ ���������� 
		public: virtual property PaddingMode Padding 
		{ 
			// ������ ���������� 
			PaddingMode get() override { return padding; }
		}
		// ���������������� ��������
		public: virtual void Init() override; 
		// ����������� ������
		public: virtual int Update(array<BYTE>^ data, 
			int dataOff, int dataLen, array<BYTE>^ buf, int bufOff) override; 
		// ��������� ������������ ������
		public:	virtual int Finish(array<BYTE>^ data, 
			int dataOff, int dataLen, array<BYTE>^ buf, int bufOff) override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� �������������
	///////////////////////////////////////////////////////////////////////////
	public ref class Decryption : Transform
	{
		private: Cipher^			cipher;		// �������� ����������
		private: PaddingMode		padding;	// ����� ����������
		private: ISecretKey^		key;		// �������� ����� ����������
		private: Using<KeyHandle^>	hKey;		// ��������� �����
		private: array<BYTE>^		lastBlock;	// �������� ���������� �����   

		// �����������
		public: Decryption(Cipher^ cipher, PaddingMode padding, ISecretKey^ key) 
		{
			// ��������� ���������� ���������
            this->cipher = RefObject::AddRef(cipher); this->padding = padding;

			// ��������� ���������� ���������
			this->key = RefObject::AddRef(key); lastBlock = nullptr; 
		}
		// ����������
		public: virtual ~Decryption() 
		{ 
			// ���������� ���������� �������
			RefObject::Release(key); RefObject::Release(cipher); 
		}
		// ������ ����� ���������
		public: virtual property int BlockSize { int get() override { return cipher->BlockSize; }}
		// ������ ���������� 
		public: virtual property PaddingMode Padding 
		{ 
			// ������ ���������� 
			PaddingMode get() override { return padding; }
		}
		// ���������������� ��������
		public: virtual void Init() override; 
		// ������������ ������
		public: virtual int Update(array<BYTE>^ data, 
			int dataOff, int dataLen, array<BYTE>^ buf, int bufOff) override; 
		// ��������� �������������
		public: virtual int Finish(array<BYTE>^ data, 
			int dataOff, int dataLen, array<BYTE>^ buf, int bufOff) override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� ������������ �����
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyDerive abstract : CAPI::KeyDerive
	{
		// ����������������� ��������� � ��������
		private: CSP::Provider^ provider; private: ContextHandle^ hContext; 

		// �����������
		public: KeyDerive(CSP::Provider^ provider, ContextHandle^ hContext)
        {   
            // ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); 

			// ��������� ���������� ���������
			this->hContext = Handle::AddRef(hContext); 
		}
        // ����������
		public: virtual ~KeyDerive() 
		{ 
			// ���������� ���������� �������
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// ����������������� ��������� � ��������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
	}; 
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� �����
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyWrap abstract : CAPI::KeyWrap
	{
		// ����������������� ��������� � ��������
		private: CSP::Provider^ provider; private: ContextHandle^ hContext; 

		// �����������
		public: KeyWrap(CSP::Provider^ provider, ContextHandle^ hContext)
        {   
            // ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); 

			// ��������� ���������� ���������
			this->hContext = Handle::AddRef(hContext); 
		}
        // ����������
		public: virtual ~KeyWrap() 
		{ 
			// ���������� ���������� �������
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// ����������������� ��������� � ��������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
	};
}}}
