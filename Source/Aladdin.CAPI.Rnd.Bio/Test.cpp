#include "stdafx.h"
#include "Rand.h"
#include <time.h>

using namespace System::Threading; 
using namespace System::Globalization; 

namespace Aladdin { namespace CAPI { namespace Rnd { namespace Bio
{
	public ref class Test abstract sealed
	{
		public: static void Entry()
		{
			time_t aaa = time(0); 

			// выделить буфер для генерации
			array<BYTE>^ buffer = gcnew array<BYTE>(65535); 
/*			try { 
				// проверить наличие генератора
				Using<IRandFactory^> randFactory(gcnew LegacyRandFactory()); 
				
				// установить локализацию
				Thread::CurrentThread->CurrentCulture = gcnew CultureInfo("en-US"); 
				{
					// создать генератор случайных данных
					Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

					// сгенерировать случайные данные
					rand.Get()->Generate(buffer, 0, buffer->Length); 
				}
			}
			catch (Exception^) {}
			try {
				// проверить наличие генератора
				Using<IRandFactory^> randFactory(gcnew LegacyRandFactory()); 
				
				// установить локализацию
				Thread::CurrentThread->CurrentCulture = gcnew CultureInfo("ru-RU"); 
				{
					// создать генератор случайных данных
					Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

					// сгенерировать случайные данные
					rand.Get()->Generate(buffer, 0, buffer->Length); 
				}
			}
			catch (Exception^) {}
			try { 
				// проверить наличие генератора
				Using<IRandFactory^> randFactory(gcnew RandFactory(true)); 
				
				// установить локализацию
				Thread::CurrentThread->CurrentCulture = gcnew CultureInfo("en-US"); 
				{
					// создать генератор случайных данных
					Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

					// сгенерировать случайные данные
					rand.Get()->Generate(buffer, 0, buffer->Length); 
				}
			}
			catch (Exception^) {}
*/			
			for (int i = 0; i < 50; i++)
			try {
				// проверить наличие генератора
				Using<IRandFactory^> randFactory(gcnew RandFactory(false)); 
				
				// установить локализацию
				Thread::CurrentThread->CurrentCulture = gcnew CultureInfo("ru-RU"); 
				{
					// создать генератор случайных данных
					Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

					// сгенерировать случайные данные
					rand.Get()->Generate(buffer, 0, buffer->Length); 
				}
			}
			catch (Exception^) {}
		}
    };
}}}}
