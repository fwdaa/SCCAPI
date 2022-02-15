#include "stdafx.h"
#include "Rand.h"

namespace Aladdin { namespace CAPI { namespace Rnd { namespace Sobol
{
	public ref class Test abstract sealed
	{
		public: static void Entry()
		{
			try { 
				// ��������� ������� ����������
				Using<IRandFactory^> randFactory(gcnew RandFactory()); 
				
				// �������� ����� ��� ���������
				array<BYTE>^ buffer = gcnew array<BYTE>(65535); 

				// ������� ��������� ��������� ������
				Using<IRand^> rand(randFactory.Get()->CreateRand(nullptr)); 

				// ������������� ��������� ������
				rand.Get()->Generate(buffer, 0, buffer->Length); 
			}
			catch (Exception^) {}
		}
    };
}}}}
