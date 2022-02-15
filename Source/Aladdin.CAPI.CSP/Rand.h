#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////
	// Датчик случайных чисел
	///////////////////////////////////////////////////////////////////////
	public ref class Rand : RefObject, IRand
	{
		// описатель контекста 
		private: ContextHandle^ hContext; private: Object^ window;  

		// конструктор
		public: Rand(ContextHandle^ hContext, Object^ window) 
		{ 
			// сохранить описатель контекста
			this->hContext = CSP::Handle::AddRef(hContext); this->window = window; 
		}
		// деструктор
		protected: virtual ~Rand() { CSP::Handle::Release(hContext); }

		// описатель контекста
		protected: property ContextHandle^ Handle { ContextHandle^ get() { return hContext; }}

		// сгенерировать случайные данные
		public: virtual void Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen)
		{
			// сгенерировать случайные данные
			hContext->Generate(buffer, bufferOff, bufferLen); 
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
	///////////////////////////////////////////////////////////////////////
	// Усиленный датчик случайных чисел
	///////////////////////////////////////////////////////////////////////
	public ref class HardwareRand : Rand
	{
		// конструктор
		public: HardwareRand(ContextHandle^ hContext, Object^ window); 

		// сгенерировать случайные данные
		public: virtual void Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen) override; 
	};
}}}
