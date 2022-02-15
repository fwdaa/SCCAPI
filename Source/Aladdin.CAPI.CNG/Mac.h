#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////
	// Алгоритм выработки имитовставки
	///////////////////////////////////////////////////////////////////////
	public ref class Mac abstract : CAPI::Mac
	{
		private: Using<BProviderHandle^> hProvider;	// криптографический контекст 
		private: Using<BHashHandle^>	 hHash;		// алгоритм вычисления имитовставки 
		
		// конструктор
		protected: Mac(String^ provider, String^ name, DWORD flags) 

			// сохранить описатель провайдера алгоритма
			: hProvider(gcnew BProviderHandle(provider, name, flags)) {}

		// размер имитовставки в байтах
		public:	virtual property int MacSize  
		{ 
			// размер имитовставки в байтах
			int get() override { return hProvider.Get()->GetLong(BCRYPT_HASH_LENGTH, 0); } 
		}
		// инициализировать алгоритм
		public: virtual void Init(ISecretKey^ key) override; 
		// захэшировать данные
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override; 
		// получить имитовставку
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override; 
	};
}}}

