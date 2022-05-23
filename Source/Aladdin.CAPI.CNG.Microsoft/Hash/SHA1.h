#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� SHA1
	///////////////////////////////////////////////////////////////////////////
	public ref class SHA1 : CAPI::CNG::Hash
	{
		// �����������
		public: SHA1(String^ provider) : Hash(provider, BCRYPT_SHA1_ALGORITHM, 0) {} 

		// ������ ���-�������� � ����� � ������
		public: virtual property int HashSize  { int get() override { return 20; } }  
		public: virtual property int BlockSize { int get() override { return 64; } }   
	};
}}}}}
