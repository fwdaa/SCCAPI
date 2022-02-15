#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования
	///////////////////////////////////////////////////////////////////////
	public ref class Hash abstract : CAPI::Hash
	{
		private: String^				 name;		// имя алгоритма
		private: Using<BProviderHandle^> hProvider;	// криптографический контекст 
		private: Using<BHashHandle^>	 hHash;		// алгоритм хэширования 
		
		// конструктор
		protected: Hash(String^ provider, String^ name, DWORD flags) 

			// сохранить описатель провайдера алгоритма
			: hProvider(gcnew BProviderHandle(provider, name, flags)) {	this->name = name; }

		// имя алгоритма
		public: property String^ Name {String^ get() { return name; } }

		// размер хэш-значения в байтах
		public:	virtual property int HashSize  
		{ 
			// размер хэш-значения в байтах
			int get() override { return hProvider.Get()->GetLong(BCRYPT_HASH_LENGTH, 0); } 
		}
		// инициализировать алгоритм
		public: virtual void Init() override;  
		// захэшировать данные
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override; 
		// получить хэш-значение
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override; 
	};
}}}