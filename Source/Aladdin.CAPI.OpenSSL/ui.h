#pragma once
#include "Aladdin.CAPI.OpenSSL.hpp"

namespace Aladdin { namespace CAPI { namespace OpenSSL {

///////////////////////////////////////////////////////////////////////////////
// Способ аутентификации с использование диалоговых окон
///////////////////////////////////////////////////////////////////////////////
class PasswordAuthentication : public IPasswordAuthentication
{
	// функция обратного вызова при вводе пароля
	public: virtual bool PasswordCallback(const char*, 
		const char*, char*, size_t, char*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Способ аутентификации с использованием консоли
///////////////////////////////////////////////////////////////////////////////
class ConsoleAuthentication : public PasswordAuthentication
{
	// способ взаимодействия с пользователем
	public: virtual UI_METHOD* CreateInputMethod(const char*) const override
	{
		// способ взаимодействия с пользователем
		return UI_OpenSSL(); 
	}
};

namespace WxWidgets
{
// Способ взаимодействия с пользователем
UI_METHOD* UI_GUI(void* pParent, const char* szTarget); 

///////////////////////////////////////////////////////////////////////////////
// Способ аутентификации с использование диалоговых окон
///////////////////////////////////////////////////////////////////////////////
class DialogAuthentication : public PasswordAuthentication
{
	// конструктор/деструктор
	public: DialogAuthentication(void* pParent) 
	
		// сохранить переданные параметры
		{ this->pParent = pParent; } private: void* pParent; 

	// способ взаимодействия с пользователем
	public: virtual UI_METHOD* CreateInputMethod(const char* szTarget) const override
	{
		// способ взаимодействия с пользователем
		return UI_GUI(pParent, szTarget); 
	}
};
}
}}}
