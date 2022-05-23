#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� DESX
	///////////////////////////////////////////////////////////////////////////
	public ref class DESX : CAPI::CSP::BlockCipher
	{
		// �����������
		public: DESX(CAPI::CSP::Provider^ provider) 

            // ��������� ���������� ���������
			: CAPI::CSP::BlockCipher(provider, provider->Handle) {} 

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return ANSI::Keys::DESX::Instance; }
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8; }}
	};
}}}}}
