#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Cipher
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� DES
	///////////////////////////////////////////////////////////////////////////
	public ref class DES : CAPI::CSP::BlockCipher
	{
		// �����������
		public: DES(CAPI::CSP::Provider^ provider) 

            // ��������� ���������� ���������
			: CAPI::CSP::BlockCipher(provider, provider->Handle) {} 

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return Keys::DES::Instance; }
		}
		// ������ ����� � ������
		public: virtual property array<int>^ KeySizes 
		{ 
			// ������ ����� � ������
			array<int>^ get() override { return gcnew array<int> {8}; } 
		}
		// ������ �����
		public: virtual property int BlockSize { int get() override { return 8; }}

		// ������� ����� ����������
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode) override
		{
			// ��� ������ CBC ���������� ���������� ����� ������������ NTE_DOUBLE_ENCRYPT
			if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
			{
				// ��������� �������������� ����
				CipherMode::CBC^ parameters = (CipherMode::CBC^)mode; 

                // �������� �������� ���������� �����
                Using<CAPI::Cipher^> engine(CreateBlockMode(gcnew CipherMode::ECB())); 
                
				// ������� ����� ���������
				return gcnew CAPI::Mode::CBC(engine.Get(), parameters, PaddingMode::Any); 
			}
			// ������� ������� ����������
			return CAPI::CSP::BlockCipher::CreateBlockMode(mode); 
		}
	};
}}}}}}
