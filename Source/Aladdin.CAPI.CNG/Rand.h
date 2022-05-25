#pragma once

#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////
	// Датчик случайных чисел
	///////////////////////////////////////////////////////////////////////
	public ref class Rand : RefObject, IRand
	{
		// криптографический контекст и описатель окна
		private: Using<BProviderHandle^> hProvider; private: Object^ window; 

		// конструктор
		public: Rand(String^ provider, String^ alg, DWORD flags, Object^ window) 

            // сохранить описатель провайдера алгоритма
			: hProvider(gcnew BProviderHandle(provider, alg, flags)) { this->window = window; }

        // изменить окно для генератора
		public: virtual IRand^ CreateRand(Object^ window) 
        { 
			// изменить окно для генератора
            return CAPI::Rand::Rebind(this, window); 
        } 
		// сгенерировать случайные данные
		public: virtual void Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen)
		{
			// сгенерировать случайные данные
			hProvider.Get()->Generate(buffer, bufferOff, bufferLen, 0); 
		}
		// сгенерировать случайные данные
		public: virtual array<BYTE>^ Generate(int bufferLen)
		{
			// выделить буфер требуемого размера
			array<BYTE>^ buffer = gcnew array<BYTE>(bufferLen); 

			// сгенерировать случайные данные
			Generate(buffer, 0, bufferLen); return buffer; 
		}
		// описатель окна, связанного с генератором
		public: virtual property Object^ Window { Object^ get() { return window; }}	
	};
}}}
