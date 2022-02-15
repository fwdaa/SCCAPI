#pragma once 
#include "AppletAuth.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Pro
{
	///////////////////////////////////////////////////////////////////////////
	// —ервис двухсторонней аутентификации апплета Pro
	///////////////////////////////////////////////////////////////////////////
	public ref class LibResponseService : LibPinService
    {
        // конструктор
		public: LibResponseService(LibApplet^ applet, String^ user)

			// сохранить переданные параметры
			: LibPinService(applet, user, true) {}

        // установить пароль
        public: virtual void SetPassword(String^ pinCode) override; 

		// получить salt-значение
		private: array<BYTE>^ GetSalt(); 
    }; 
	///////////////////////////////////////////////////////////////////////////
	// —ервис двухсторонней аутентификации апплета Pro Java
	///////////////////////////////////////////////////////////////////////////
	public ref class LibResponseServiceJava : LibPinService
    {
        // конструктор
		public: LibResponseServiceJava(LibApplet^ applet, String^ user)

			// сохранить переданные параметры
			: LibPinService(applet, user, true) {}

        // установить пароль
        public: virtual void SetPassword(String^ pinCode) override; 

		// получить salt-значение
		private: array<BYTE>^ GetSalt(); 
	}; 
}
}}}}
