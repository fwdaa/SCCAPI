#pragma once

namespace Aladdin { namespace CAPI { namespace Rnd { namespace Accord 
{
	///////////////////////////////////////////////////////////////////////
	// ��������� ��������� ������
	///////////////////////////////////////////////////////////////////////
	public ref class Rand : RefObject, IRand
	{
		// ��� ������� ���������
		public: typedef DWORD (*PFNGENERATE)(PVOID, DWORD); 

		// ������� � ����� �������
		private: IRandFactory^ factory; PFNGENERATE pfnGenerate; Object^ window;  

		// �����������
		public: Rand(IRandFactory^ factory, PFNGENERATE pfnGenerate, Object^ window)
		{
			// ��������� ������� �����������
			this->factory = factory; factory->AddRef(); 

			// ��������� ���������� ���������
			this->pfnGenerate = pfnGenerate; this->window = window; 
		}
		// ����������
		protected: virtual ~Rand() { factory->Release(); }

		// ������������� ��������� ������
		public: virtual void Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen); 

		// ������������� ��������� ������
		public: virtual array<BYTE>^ Generate(int bufferLen)
		{
			// �������� ����� ���������� �������
			array<BYTE>^ buffer = gcnew array<BYTE>(bufferLen); 

			// ������������� ��������� ������
			Generate(buffer, 0, bufferLen); return buffer; 
		}
		// ��������� ����, ���������� � �����������
		public: virtual property Object^ Window { Object^ get() { return window; }}	
	};
	///////////////////////////////////////////////////////////////////////
	// ������� �������� ����������� ��������� ������
	///////////////////////////////////////////////////////////////////////
	public ref class RandFactory : RefObject, IRandFactory
	{
		// ��������� ������ � ����� �������
		private: HMODULE hModule; Rand::PFNGENERATE pfnGenerate; 

		// �����������/����������
		public: RandFactory(); protected: virtual ~RandFactory(); 

		// ������� ��������� ��������� ������
		public: virtual IRand^ CreateRand(Object^ window) 
		{ 
			// ������� ��������� ��������� ������
			return gcnew Rand(this, pfnGenerate, window);  
		}
	};
}}}}

