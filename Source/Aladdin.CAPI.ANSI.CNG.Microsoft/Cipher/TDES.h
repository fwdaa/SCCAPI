#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// �������� ���������� ����� TDES
	///////////////////////////////////////////////////////////////////////////////
	public ref class TDES : CAPI::CNG::BlockCipher
	{
		// ������� ������
		private: array<int>^ keySizes; 

		// �����������
		public: TDES(String^ provider, array<int>^ keySizes) 
			
			// ��������� ���������� ���������
			: CAPI::CNG::BlockCipher(provider) { this->keySizes = keySizes; }
		 
        // ��� ��������� ����������
		public: virtual String^ GetName(int keySize) override  
		{
			// ��� ��������� ����������
			return (keySize == 24) ? BCRYPT_3DES_ALGORITHM : BCRYPT_3DES_112_ALGORITHM; 
		}
		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return gcnew Keys::TDES(keySizes); }
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8; }} 
	};
}}}}}}
