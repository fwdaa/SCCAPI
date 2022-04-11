#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// �������� ���������� ����� DES
	///////////////////////////////////////////////////////////////////////////////
	public ref class DES : CAPI::CNG::BlockCipher
	{
		// �����������
		public: DES(String^ provider) : CAPI::CNG::BlockCipher(provider) {}
		 
        // ��� ��������� ����������
		public: virtual String^ GetName(int keySize) override { return BCRYPT_DES_ALGORITHM; }

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return Keys::DES::Instance; }
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8; }} 
	};
}}}}}}
