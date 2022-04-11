#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� AES-128
	///////////////////////////////////////////////////////////////////////////
	public ref class AES : CAPI::CSP::BlockCipher
	{
		private: array<int>^ keySizes; 

		// �����������
		public: AES(CAPI::CSP::Provider^ provider, array<int>^ keySizes) 

            // ��������� ���������� ���������
			: CAPI::CSP::BlockCipher(provider, provider->Handle) { this->keySizes = keySizes; } 

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
