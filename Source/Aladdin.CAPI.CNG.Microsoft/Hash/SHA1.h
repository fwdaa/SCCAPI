#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования SHA1
	///////////////////////////////////////////////////////////////////////////
	public ref class SHA1 : CAPI::CNG::Hash
	{
		// конструктор
		public: SHA1(String^ provider) : Hash(provider, BCRYPT_SHA1_ALGORITHM, 0) {} 

		// размер хэш-значения и блока в байтах
		public: virtual property int HashSize  { int get() override { return 20; } }  
		public: virtual property int BlockSize { int get() override { return 64; } }   
	};
}}}}}
