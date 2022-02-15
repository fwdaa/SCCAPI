#pragma once
#include "Applet.h"
#include "LaserFormat.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Laser
{
    ///////////////////////////////////////////////////////////////////////////
	// Апплет Laser
    ///////////////////////////////////////////////////////////////////////////
	ref class Applet : LibApplet
	{
        // конструктор
		public: static Applet^ Create(SCard::Card^ store, 
			PCSC::ReaderSession^ session, array<BYTE>^ atr) 
		{
			// создать апплет
			Applet^ applet = gcnew Applet(store, session, atr); 

			// вернуть прокси
			try { return (Applet^)Proxy::SecurityObjectProxy::Create(applet); }

			// обработать возможную ошибку
			catch (Exception^) { delete applet; throw; } 
		}
        // конструктор
		protected: Applet(SCard::Card^ store, PCSC::ReaderSession^ session, array<BYTE>^ atr) 
			
			// сохранить переданные параметры
			: LibApplet(store, "Laser", libapdu::TAppletAthena, session, atr) {}

		// серийный номер смарт-карты
		public: virtual array<BYTE>^ GetSerial() override;  

        ///////////////////////////////////////////////////////////////////////
        // Форматирование апплета 
        ///////////////////////////////////////////////////////////////////////

        // параметры форматирования по умолчанию
		public: virtual SCard::FormatParameters^ GetDefaultFormatParameters() override
		{
			// параметры форматирования по умолчанию
			return gcnew FormatParameters(); 
		}
        // выполнить форматирование апплета
		public: virtual void Format(String^ adminPIN, SCard::FormatParameters^ parameters) override;  

        ///////////////////////////////////////////////////////////////////////
        // Аутентификация 
        ///////////////////////////////////////////////////////////////////////

		// признак наличия аутентификации администратора
		protected: virtual int HasAdminAuthentication() override;  

		// поддерживаемые типы аутентификации
		public: virtual array<Type^>^GetAuthenticationTypes(String^ user) override; 

		// получить протокол аутентификации
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override; 
	};
}}}}}

