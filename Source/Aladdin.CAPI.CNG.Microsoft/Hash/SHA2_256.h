#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования SHA-256
	///////////////////////////////////////////////////////////////////////////
	public ref class SHA2_256 : CAPI::CNG::Hash
	{
		// конструктор
		public: SHA2_256(String^ provider) : Hash(provider, BCRYPT_SHA256_ALGORITHM, 0) {} 

		// размер хэш-значения и блока в байтах
		public: virtual property int HashSize  { int get() override { return 32; } }  
		public: virtual property int BlockSize { int get() override { return 64; } }   
	};
}}}}}
