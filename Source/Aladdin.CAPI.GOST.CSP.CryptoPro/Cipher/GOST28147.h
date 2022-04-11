#pragma once
#include "..\MAC\MAC_GOST28147.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// ������� �������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class GOST28147 : CAPI::CSP::BlockCipher
	{
		// ������������� ������� ����������� � ������ ����� �����
		private: String^ sboxOID; private: String^ meshing;

		// �����������
		public: GOST28147(CAPI::CSP::Provider^ provider, 
			CAPI::CSP::ContextHandle^ hContext, String^ sboxOID, String^ meshing)

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
			SecretKeyFactory^ get() override { return Keys::GOST::Instance; }
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8; }} 

		// ������� ����� ����������
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode) override; 

		// ���������� ��������� ���������
		public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override; 

		///////////////////////////////////////////////////////////////////////////
		// ����� ��������� ���������� ���� 28147-89
		///////////////////////////////////////////////////////////////////////////
		public: ref class BlockMode : CAPI::CSP::BlockMode
		{
			// �����������
			public: BlockMode(CAPI::CSP::BlockCipher^ blockCipher, CipherMode^ mode, 

				// ��������� ���������� ���������
				PaddingMode padding) : CAPI::CSP::BlockMode(blockCipher, mode, padding) {}
			
			// ���������� ��������� ��������� ����������
			public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey, PaddingMode padding) override;
		};
	};
}}}}}}
