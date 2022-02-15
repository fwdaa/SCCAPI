#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ���������� ������������ HMAC
	///////////////////////////////////////////////////////////////////////////
	public ref class HMAC : CAPI::CNG::Mac
	{
		// ������ ����� � ������
		private: DWORD blockSize; 

		// �����������
		public: HMAC(String^ provider, String^ hash, DWORD blockSize) 

			// ��������� ���������� ���������
			: CAPI::CNG::Mac(provider, hash, BCRYPT_ALG_HANDLE_HMAC_FLAG) { this->blockSize = blockSize; } 

		// ������ ����� � ������
		public:	virtual property int BlockSize { int get() override { return blockSize; } }
	};
}}}}}}

