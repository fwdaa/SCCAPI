#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������� MD2
	///////////////////////////////////////////////////////////////////////////
	public ref class MD2 : CAPI::CNG::Hash
	{
		// �����������
		public: MD2(String^ provider) : Hash(provider, BCRYPT_MD2_ALGORITHM, 0) {} 

		// ������ ���-�������� � ����� � ������
		public: virtual property int HashSize  { int get() override { return 16; } }  
		public: virtual property int BlockSize { int get() override { return 64; } }   
	};
}}}}}
