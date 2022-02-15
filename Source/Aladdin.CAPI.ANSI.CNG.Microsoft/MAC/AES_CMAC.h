#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ������������ AES GMAC
	///////////////////////////////////////////////////////////////////////////
	public ref class AES_CMAC : CAPI::CNG::Mac
	{
		// �����������
		public: AES_CMAC(String^ provider, array<int>^ keySizes) 
			: CAPI::CNG::Mac(provider, "AES-CMAC", 0) 

			// ��������� ���������� ���������
			{ this->keySizes = keySizes; } private: array<int>^ keySizes; 

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// ��� �����
			SecretKeyFactory^ get() override { return Keys::AES::Instance; }
		}
		// ������ ���������� ������
		public: virtual property array<int>^ KeySizes 
		{ 
			// ������ ���������� ������
			array<int>^ get() override { return keySizes; }
		}
		// ������ ����� � ������
		public:	virtual property int BlockSize { int get() override { return 16; } }
	};
}}}}}}
