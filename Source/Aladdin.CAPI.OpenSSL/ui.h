#pragma once
#include "Aladdin.CAPI.OpenSSL.hpp"

namespace Aladdin { namespace CAPI { namespace OpenSSL {

///////////////////////////////////////////////////////////////////////////////
// ������ �������������� � ������������� ���������� ����
///////////////////////////////////////////////////////////////////////////////
class PasswordAuthentication : public IPasswordAuthentication
{
	// ������� ��������� ������ ��� ����� ������
	public: virtual bool PasswordCallback(const char*, 
		const char*, char*, size_t, char*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������ �������������� � �������������� �������
///////////////////////////////////////////////////////////////////////////////
class ConsoleAuthentication : public PasswordAuthentication
{
	// ������ �������������� � �������������
	public: virtual UI_METHOD* CreateInputMethod(const char*) const override
	{
		// ������ �������������� � �������������
		return UI_OpenSSL(); 
	}
};

namespace WxWidgets
{
// ������ �������������� � �������������
UI_METHOD* UI_GUI(void* pParent, const char* szTarget); 

///////////////////////////////////////////////////////////////////////////////
// ������ �������������� � ������������� ���������� ����
///////////////////////////////////////////////////////////////////////////////
class DialogAuthentication : public PasswordAuthentication
{
	// �����������/����������
	public: DialogAuthentication(void* pParent) 
	
		// ��������� ���������� ���������
		{ this->pParent = pParent; } private: void* pParent; 

	// ������ �������������� � �������������
	public: virtual UI_METHOD* CreateInputMethod(const char* szTarget) const override
	{
		// ������ �������������� � �������������
		return UI_GUI(pParent, szTarget); 
	}
};
}
}}}
