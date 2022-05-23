#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования MD5
	///////////////////////////////////////////////////////////////////////////
	public ref class MD5 : CAPI::CNG::Hash
	{
		// конструктор
		public: MD5(String^ provider) : Hash(provider, BCRYPT_MD5_ALGORITHM, 0) {} 

		// размер хэш-значения и блока в байтах
		public: virtual property int HashSize  { int get() override { return 16; } }  
		public: virtual property int BlockSize { int get() override { return 64; } }   
	};
}}}}}
