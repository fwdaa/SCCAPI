#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� RC4
	///////////////////////////////////////////////////////////////////////////
	public ref class RC4 : CAPI::CNG::Cipher
	{
		// �����������
		public: RC4(String^ provider, array<int>^ keySizes) : CAPI::CNG::Cipher(provider) 
		
			// ��������� ���������� ���������
			{ this->keySizes = keySizes; } private: array<int>^ keySizes; 

        // ��� ��������� ����������
		public: virtual String^ GetName(int keySize) override { return BCRYPT_RC4_ALGORITHM; }

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return gcnew Keys::RC4(keySizes); }
		}
	};
}}}}}}
