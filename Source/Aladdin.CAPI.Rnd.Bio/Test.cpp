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

			// �������� ����� ��� ���������
			array<BYTE>^ buffer = gcnew array<BYTE>(65535); 
/*			try { 
				// ��������� ������� ����������
				Using<IRandFactory^> randFactory(gcnew LegacyRandFactory()); 
				
				// ���������� �����������
				Thread::CurrentThread->CurrentCulture = gcnew CultureInfo("en-US"); 
				{
					// ������� ��������� ��������� ������
					Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

					// ������������� ��������� ������
					rand.Get()->Generate(buffer, 0, buffer->Length); 
				}
			}
			catch (Exception^) {}
			try {
				// ��������� ������� ����������
				Using<IRandFactory^> randFactory(gcnew LegacyRandFactory()); 
				
				// ���������� �����������
				Thread::CurrentThread->CurrentCulture = gcnew CultureInfo("ru-RU"); 
				{
					// ������� ��������� ��������� ������
					Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

					// ������������� ��������� ������
					rand.Get()->Generate(buffer, 0, buffer->Length); 
				}
			}
			catch (Exception^) {}
			try { 
				// ��������� ������� ����������
				Using<IRandFactory^> randFactory(gcnew RandFactory(true)); 
				
				// ���������� �����������
				Thread::CurrentThread->CurrentCulture = gcnew CultureInfo("en-US"); 
				{
					// ������� ��������� ��������� ������
					Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

					// ������������� ��������� ������
					rand.Get()->Generate(buffer, 0, buffer->Length); 
				}
			}
			catch (Exception^) {}
*/			
			for (int i = 0; i < 50; i++)
			try {
				// ��������� ������� ����������
				Using<IRandFactory^> randFactory(gcnew RandFactory(false)); 
				
				// ���������� �����������
				Thread::CurrentThread->CurrentCulture = gcnew CultureInfo("ru-RU"); 
				{
					// ������� ��������� ��������� ������
					Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

					// ������������� ��������� ������
					rand.Get()->Generate(buffer, 0, buffer->Length); 
				}
			}
			catch (Exception^) {}
		}
    };
}}}}
