#pragma once

namespace Aladdin { namespace CAPI { namespace Rnd { namespace Sobol
{
	///////////////////////////////////////////////////////////////////////
	// √енератор случайных данных
	///////////////////////////////////////////////////////////////////////
	public ref class Rand : RefObject, IRand
	{
		// тип функции генерации
		public: typedef SNCODE (__stdcall *PFNGENERATE)(PVOID, DWORD); 

		// фабрика и адрес функции
		private: IRandFactory^ factory; PFNGENERATE pfnGenerate; Object^ window;  

		// конструктор
		public: Rand(IRandFactory^ factory, PFNGENERATE pfnGenerate, Object^ window)
		{
			// сохранить фабрику генераторов
			this->factory = factory; factory->AddRef(); 

			// сохранить переданные параметры
			this->pfnGenerate = pfnGenerate; this->window = window; 
		}
		// деструктор
		protected: virtual ~Rand() { factory->Release(); }

        // изменить окно дл€ генератора
		public: virtual IRand^ CreateRand(Object^ window) 
        { 
			// изменить окно дл€ генератора
            return CAPI::Rand::Rebind(this, window); 
        } 
		// сгенерировать случайные данные
		public: virtual void Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen); 

		// сгенерировать случайные данные
		public: virtual array<BYTE>^ Generate(int bufferLen)
		{
			// выделить буфер требуемого размера
			array<BYTE>^ buffer = gcnew array<BYTE>(bufferLen); 

			// сгенерировать случайные данные
			Generate(buffer, 0, bufferLen); return buffer; 
		}
		// описатель окна, св€занного с генератором
		public: virtual property Object^ Window { Object^ get() { return window; }}	
	};
	///////////////////////////////////////////////////////////////////////
	// ‘абрика создани€ генераторов случайных данных
	///////////////////////////////////////////////////////////////////////
	public ref class RandFactory : RefObject, IRandFactory
	{
		// описатель модул€ и адрес функции
		private: HMODULE hModule; Rand::PFNGENERATE pfnGenerate; 

		// конструктор/деструктор
		public: RandFactory(); protected: virtual ~RandFactory(); 

		// создать генератор случайных данных
		public: virtual IRand^ CreateRand(Object^ window) 
		{ 
			// создать генератор случайных данных
			return gcnew Rand(this, pfnGenerate, window);  
		}
	};
}}}}

