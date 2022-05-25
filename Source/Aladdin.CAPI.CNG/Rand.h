#pragma once

#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////
	// ������ ��������� �����
	///////////////////////////////////////////////////////////////////////
	public ref class Rand : RefObject, IRand
	{
		// ����������������� �������� � ��������� ����
		private: Using<BProviderHandle^> hProvider; private: Object^ window; 

		// �����������
		public: Rand(String^ provider, String^ alg, DWORD flags, Object^ window) 

            // ��������� ��������� ���������� ���������
			: hProvider(gcnew BProviderHandle(provider, alg, flags)) { this->window = window; }

        // �������� ���� ��� ����������
		public: virtual IRand^ CreateRand(Object^ window) 
        { 
			// �������� ���� ��� ����������
            return CAPI::Rand::Rebind(this, window); 
        } 
		// ������������� ��������� ������
		public: virtual void Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen)
		{
			// ������������� ��������� ������
			hProvider.Get()->Generate(buffer, bufferOff, bufferLen, 0); 
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
}}}
