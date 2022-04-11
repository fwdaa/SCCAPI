#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// �������� ���������� ����� RC2
	///////////////////////////////////////////////////////////////////////////////
	public ref class RC2 : CAPI::CNG::BlockCipher
	{
		// ����������� ����� ����� � ������� ������
		private: int effectiveKeyBits; private: array<int>^ keySizes; 

		// �����������
		public: RC2(String^ provider, int effectiveKeyBits, array<int>^ keySizes)
			
			// ��������� ���������� ���������
			: CAPI::CNG::BlockCipher(provider) 
		{ 
			// ��������� ���������� ���������
			this->effectiveKeyBits = effectiveKeyBits; this->keySizes = keySizes; 
		} 
        // ��� ��������� ����������
		public: virtual String^ GetName(int keySize) override { return BCRYPT_RC2_ALGORITHM; }

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return gcnew Keys::RC2(keySizes); }
		}
		// ������ ����� � ����� �� ���������
		public: virtual property int BlockSize  { int get() override { return 8; }} 

		// ���������� ��������� ���������
		public: virtual void SetParameters(CAPI::CNG::BProviderHandle^ hKey) override
		{
			// ������� �������� ���������
			hKey->SetLong(BCRYPT_EFFECTIVE_KEY_LENGTH, effectiveKeyBits, 0); 
		}
	};
}}}}}}
