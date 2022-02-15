#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class Cipher abstract : CAPI::Cipher
	{
		// �����������
		public: Cipher(String^ provider)
		
			// ��������� ���������� ���������
			{ this->provider = provider; } private: String^ provider; 

		// ��� ����������
		public: property String^ Provider { String^ get() { return provider; }}

        // ��� ��������� ����������
		public: virtual String^ GetName(int keySize) = 0; 
		// ���������� ��������� ���������
		public protected: virtual array<BYTE>^ SetParameters(BProviderHandle^ hProvider) { return nullptr; } 

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
		// �����������
		public: BlockCipher(String^ provider)

			// ��������� ���������� ���������
			{ this->provider = provider; } private: String^ provider; 

		// ��� ����������
		public: property String^ Provider { String^ get() { return provider; }}

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory { SecretKeyFactory^ get() = 0; }
		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes { array<int>^ get() = 0; }
		// ������ �����
		public: virtual property int BlockSize { int get()  = 0; }

		// ������� ����� ����������
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode); 

        // ��� ��������� ����������
		public: virtual String^ GetName(int keySize) = 0; 
		// ���������� ��������� ���������
		public protected: virtual void SetParameters(BProviderHandle^ hProvider) {} 
	};
	///////////////////////////////////////////////////////////////////////////
	// ������� �������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockMode : Cipher
	{
		// ������� �������� ����������, ����� ��������� � ������ ����������
		private: BlockCipher^ blockCipher; CipherMode^ mode; PaddingMode padding;

		// �����������
		public: BlockMode(BlockCipher^ blockCipher, 
			CipherMode^ mode, PaddingMode padding) : Cipher(blockCipher->Provider)
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

        // ��� ��������� ����������
		public: virtual String^ GetName(int keySize) override 
		{
			// ��� ��������� ����������
			return blockCipher->GetName(keySize); 
		}
		// ���������� ��������� ���������
		public protected: virtual array<BYTE>^ SetParameters(
			BProviderHandle^ hProvider) override; 

        // ������� ����� ����������
		protected: virtual BlockPadding^ GetPadding(); 
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� ������������
	///////////////////////////////////////////////////////////////////////////
	private ref class Encryption : Transform
	{
		private: Cipher^				 cipher;	// ������� �������� ����������
		private: PaddingMode			 padding;	// ����� ���������� �����
		private: array<BYTE>^			 key;		// �������� ����� ����������
		private: Using<BProviderHandle^> hProvider;	// ����������������� ��������
		private: Using<BKeyHandle^>		 hKey;		// ��������� �����
		private: array<BYTE>^			 iv;		// ������� �������� �������������

		// �����������
		public: Encryption(Cipher^ cipher, PaddingMode padding, array<BYTE>^ key)

			// ������� ����������������� ��������
			: hProvider(gcnew BProviderHandle(cipher->Provider, cipher->GetName(key->Length), 0))
		{
            // ��������� ���������� ���������
			this->cipher = RefObject::AddRef(cipher); 
			 
            // ��������� ���������� ���������
			this->padding = padding; this->key = key; this->iv = nullptr; 
		}
		// ����������
		public: virtual ~Encryption() { RefObject::Release(cipher); }

		// ������ ����� ���������
		public: virtual property int BlockSize  { int get() override { return cipher->BlockSize;  }}
		// ����� ���������� ���������
		public: virtual property PaddingMode Padding 
		{ 
			// ����� ���������� ���������
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
	private ref class Decryption : Transform
	{
		private: Cipher^				 cipher;	// ������� �������� ����������
		private: PaddingMode			 padding;	// ����� ���������� �����
		private: array<BYTE>^			 key;		// �������� ����� ����������
		private: Using<BProviderHandle^> hProvider;	// ����������������� ��������
		private: Using<BKeyHandle^>		 hKey;		// ��������� �����
		private: array<BYTE>^			 iv;		// ������� �������� �������������
		private: array<BYTE>^			 lastBlock;	// �������� ���������� �����   
		
		// �����������
		public: Decryption(Cipher^ cipher, PaddingMode padding, array<BYTE>^ key) 

			// ������� ����������������� ��������
			: hProvider(gcnew BProviderHandle(cipher->Provider, cipher->GetName(key->Length), 0)) 
		{
            // ��������� ���������� ���������
			this->cipher = RefObject::AddRef(cipher); this->padding = padding; 

            // ��������� ���������� ���������
			this->key = key; this->iv = nullptr; this->lastBlock = nullptr; 
		}
		// ����������
		public: virtual ~Decryption() { RefObject::Release(cipher); }

		// ������ ����� ���������
		public: virtual property int BlockSize { int get() override { return cipher->BlockSize; } }
		// ����� ���������� ���������
		public: virtual property PaddingMode Padding 
		{ 
			// ����� ���������� ���������
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
}}}
