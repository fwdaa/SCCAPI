#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
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
			SecretKeyFactory^ get() override { return Keys::TDES::Instance; }
		}
		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes 
		{ 
			// ������ ����� � ������
			array<int>^ get() override { return keySizes; } 
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8; }}
	};
}}}}}}
