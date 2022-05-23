#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� TDES
	///////////////////////////////////////////////////////////////////////////
	public ref class TDES : CAPI::CSP::BlockCipher
	{
		// �����������
		public: TDES(CAPI::CSP::Provider^ provider, array<int>^ keySizes) 

            // ��������� ���������� ���������
			: CAPI::CSP::BlockCipher(provider, provider->Handle) 
		
			// ��������� ���������� ���������
			{ this->keySizes = keySizes; } private: array<int>^ keySizes; 

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return gcnew ANSI::Keys::TDES(keySizes); }
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8; }}
	};
}}}}}
