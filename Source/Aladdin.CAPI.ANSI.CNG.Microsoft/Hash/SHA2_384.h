#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Hash
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования SHA-384
	///////////////////////////////////////////////////////////////////////////
	public ref class SHA2_384 : CAPI::CNG::Hash
	{
		// конструктор
		public: SHA2_384(String^ provider) : Hash(provider, BCRYPT_SHA384_ALGORITHM, 0) {} 

		// размер хэш-значения и блока в байтах
		public: virtual property int HashSize  { int get() override { return  48; } }  
		public: virtual property int BlockSize { int get() override { return 128; } }   
	};
}}}}}}
