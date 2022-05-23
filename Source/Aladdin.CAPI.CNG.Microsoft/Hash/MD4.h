#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� MD4
	///////////////////////////////////////////////////////////////////////////
	public ref class MD4 : CAPI::CNG::Hash
	{
		// �����������
		public: MD4(String^ provider) : Hash(provider, BCRYPT_MD4_ALGORITHM, 0) {} 

		// ������ ���-�������� � ����� � ������
		public: virtual property int HashSize  { int get() override { return 16; } }  
		public: virtual property int BlockSize { int get() override { return 64; } }   
	};
}}}}}
