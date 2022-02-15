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
			SecretKeyFactory^ get() override { return Keys::RC4::Instance; }
		}
		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes 
		{ 
			// ������ ����� � ������
			array<int>^ get() override { return keySizes; } 
		}
	};
}}}}}}
