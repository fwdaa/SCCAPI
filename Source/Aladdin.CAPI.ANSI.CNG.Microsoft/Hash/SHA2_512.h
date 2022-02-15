#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования SHA-512
	///////////////////////////////////////////////////////////////////////////
	public ref class SHA2_512 : CAPI::CNG::Hash
	{
		// конструктор
		public: SHA2_512(String^ provider) : Hash(provider, BCRYPT_SHA512_ALGORITHM, 0) {} 

		// размер хэш-значения и блока в байтах
		public: virtual property int HashSize  { int get() override { return  64; } }  
		public: virtual property int BlockSize { int get() override { return 128; } }   
	};
}}}}}}
