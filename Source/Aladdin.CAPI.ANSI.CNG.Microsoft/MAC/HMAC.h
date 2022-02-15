#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC
	///////////////////////////////////////////////////////////////////////////
	public ref class HMAC : CAPI::CNG::Mac
	{
		// размер блока в байтах
		private: DWORD blockSize; 

		// конструктор
		public: HMAC(String^ provider, String^ hash, DWORD blockSize) 

			// сохранить переданные параметры
			: CAPI::CNG::Mac(provider, hash, BCRYPT_ALG_HANDLE_HMAC_FLAG) { this->blockSize = blockSize; } 

		// размер блока в байтах
		public:	virtual property int BlockSize { int get() override { return blockSize; } }
	};
}}}}}}

