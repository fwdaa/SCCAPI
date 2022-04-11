#pragma once
#include "..\MAC\MAC_GOST28147.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// ������� �������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST28147 : CAPI::CSP::BlockCipher
	{
		// ������������� ������� ����������� � ������� ����� �����
		private: String^ sboxOID; private: bool meshing; 

		// �����������
		public: GOST28147(CAPI::CSP::Provider^ provider, 
			CAPI::CSP::ContextHandle^ hContext, String^ sboxOID, bool meshing)

			// ��������� ���������� ���������
			: CAPI::CSP::BlockCipher(provider, hContext)
		{
			// ��������� ���������� ���������
			this->sboxOID = sboxOID; this->meshing = meshing; 
		}
		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return GOST::Keys::GOST::Instance; }
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8; }} 

		// ������� ����� ����������
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode) override; 

		// ���������� ��������� ���������
		public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override; 

		///////////////////////////////////////////////////////////////////////////
		// �������� ���������� ���� 28147-89
		///////////////////////////////////////////////////////////////////////////
		public: ref class BlockMode : CAPI::CSP::BlockMode
		{
			// �����������
			public: BlockMode(CAPI::CSP::BlockCipher^ blockCipher, CipherMode^ mode, PaddingMode padding) 

				// ��������� ���������� ���������
				: CAPI::CSP::BlockMode(blockCipher, mode, padding) {} 

			// ���������� ��������� ��������� ����������
			public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey, PaddingMode padding) override;

			// �������� ������������ ������
			protected: virtual Transform^ CreateEncryption(ISecretKey^ key) override
			{
				// �������� ������������� ������������
				return gcnew CAPI::CSP::Encryption(this, PaddingMode::None, key); 
			}
			// �������� ������������� ������
			protected: virtual Transform^ CreateDecryption(ISecretKey^ key) override
			{
				// �������� ������������� ������������
				return gcnew CAPI::CSP::Decryption(this, PaddingMode::None, key); 
			}
		};
	};
}}}}}}
