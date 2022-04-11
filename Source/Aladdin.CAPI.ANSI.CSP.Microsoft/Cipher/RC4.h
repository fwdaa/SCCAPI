#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� RC4
	///////////////////////////////////////////////////////////////////////////
	public ref class RC4 : CAPI::CSP::Cipher
	{
		// �����������
		public: RC4(CAPI::CSP::Provider^ provider, array<int>^ keySizes) 

            // ��������� ���������� ���������
			: CAPI::CSP::Cipher(provider, provider->Handle) 
		 
            // ��������� ���������� ���������
			{ this->keySizes = keySizes; } private: array<int>^ keySizes;

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return gcnew Keys::RC4(keySizes); }
		}
	};
}}}}}}
