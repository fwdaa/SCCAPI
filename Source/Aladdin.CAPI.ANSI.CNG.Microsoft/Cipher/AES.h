#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// �������� ���������� ����� AES
	///////////////////////////////////////////////////////////////////////////////
	public ref class AES : CAPI::CNG::BlockCipher
	{
		// ������� ������������ ������
		private: array<int>^ keySizes; 

		// �����������
		public: AES(String^ provider, array<int>^ keySizes) 
			
			// ��������� ���������� ���������
			: CAPI::CNG::BlockCipher(provider) { this->keySizes = keySizes; } 
		 
        // ��� ��������� ����������
		public: virtual String^ GetName(int keySize) override { return BCRYPT_AES_ALGORITHM; }

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return gcnew Keys::AES(keySizes); }
		}
		// ������ ����� 
		public: virtual property int BlockSize { int get() override { return 16; }}
	};
}}}}}}
