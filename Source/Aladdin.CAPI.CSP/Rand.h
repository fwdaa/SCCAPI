#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////
	// ������ ��������� �����
	///////////////////////////////////////////////////////////////////////
	public ref class Rand : RefObject, IRand
	{
		// ��������� ��������� 
		private: ContextHandle^ hContext; private: Object^ window;  

		// �����������
		public: Rand(ContextHandle^ hContext, Object^ window) 
		{ 
			// ��������� ��������� ���������
			this->hContext = CSP::Handle::AddRef(hContext); this->window = window; 
		}
		// ����������
		protected: virtual ~Rand() { CSP::Handle::Release(hContext); }

		// ��������� ���������
		protected: property ContextHandle^ Handle { ContextHandle^ get() { return hContext; }}

		// ������������� ��������� ������
		public: virtual void Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen)
		{
			// ������������� ��������� ������
			hContext->Generate(buffer, bufferOff, bufferLen); 
		}
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
	// ��������� ������ ��������� �����
	///////////////////////////////////////////////////////////////////////
	public ref class HardwareRand : Rand
	{
		// �����������
		public: HardwareRand(ContextHandle^ hContext, Object^ window); 

		// ������������� ��������� ������
		public: virtual void Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen) override; 
	};
}}}
