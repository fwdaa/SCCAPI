#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� DESX
	///////////////////////////////////////////////////////////////////////////
	public ref class DESX : CAPI::CNG::BlockCipher
	{
		// �����������
		public: DESX(String^ provider) : CAPI::CNG::BlockCipher(provider) {}
			
        // ��� ��������� ����������
		public: virtual String^ GetName(int keySize) override { return BCRYPT_DESX_ALGORITHM; }

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return ANSI::Keys::DESX::Instance; }
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return  8; }}
	};
}}}}}
