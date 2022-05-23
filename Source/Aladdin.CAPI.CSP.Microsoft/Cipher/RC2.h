#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� RC2
	///////////////////////////////////////////////////////////////////////////
	public ref class RC2 : CAPI::CSP::BlockCipher
	{
		// ����������� ����� ����� � ������ ������
		private: DWORD effectiveKeyBits; private: array<int>^ keySizes; 

		// �����������
		public: RC2(CAPI::CSP::Provider^ provider, int effectiveKeyBits, array<int>^ keySizes) 

            // ��������� ���������� ���������
			: CAPI::CSP::BlockCipher(provider, provider->Handle) 
		{ 
			// ��������� ���������� ���������
			this->effectiveKeyBits = effectiveKeyBits; this->keySizes = keySizes; 
		} 
		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return gcnew ANSI::Keys::RC2(keySizes); }
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8; }}

		// ���������� ��������� ���������
		public: virtual void SetParameters(CAPI::CSP::KeyHandle^ hKey) override
		{
			// ������� �������� ���������
			hKey->SetLong(KP_EFFECTIVE_KEYLEN, effectiveKeyBits, 0); 
		}
	};
}}}}}
