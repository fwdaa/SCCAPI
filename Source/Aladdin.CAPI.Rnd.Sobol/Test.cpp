#include "stdafx.h"
#include "Rand.h"

namespace Aladdin { namespace CAPI { namespace Rnd { namespace Sobol
{
	public ref class Test abstract sealed
	{
		public: static void Entry()
		{
			try { 
				// проверить наличие генератора
				Using<IRandFactory^> randFactory(gcnew RandFactory()); 
				
				// выделить буфер для генерации
				array<BYTE>^ buffer = gcnew array<BYTE>(65535); 

				// создать генератор случайных данных
				Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

				// сгенерировать случайные данные
				rand.Get()->Generate(buffer, 0, buffer->Length); 
			}
			catch (Exception^) {}
		}
    };
}}}}
