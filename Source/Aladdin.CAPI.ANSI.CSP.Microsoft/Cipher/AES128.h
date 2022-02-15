#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� AES-128
	///////////////////////////////////////////////////////////////////////////
	public ref class AES128 : CAPI::CSP::BlockCipher
	{
		// �����������
		public: AES128(CAPI::CSP::Provider^ provider) 

            // ��������� ���������� ���������
			: CAPI::CSP::BlockCipher(provider, provider->Handle) {} 

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return Keys::AES::Instance; }
		}
		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes 
		{ 
			// ������ ����� � ������
			array<int>^ get() override { return gcnew array<int> {16}; } 
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 16; }}
	};
}}}}}}
