#pragma once

namespace Aladdin { namespace CAPI { namespace Rnd { namespace Bio
{
	///////////////////////////////////////////////////////////////////////
	// ������� �������� ����������� ��������� ������ (����� �������������)
	///////////////////////////////////////////////////////////////////////
	public ref class LegacyRandFactory : RefObject, IRandFactory
	{
		// ������� ��������� ��������� ������
		public: virtual IRand^ CreateRand(Object^ window);  
	};
	///////////////////////////////////////////////////////////////////////
	// ������� �������� ����������� ��������� ������ (��� ������������)
	///////////////////////////////////////////////////////////////////////
	public ref class RandFactory : RefObject, IRandFactory
	{
		// �����������
		public: RandFactory(bool anyChar) { this->anyChar = anyChar; } 
		// �����������
		public: RandFactory() { anyChar = false; } private: bool anyChar; 

		// ������� ��������� ��������� ������
		public: virtual IRand^ CreateRand(Object^ window);  
	};
}}}}
