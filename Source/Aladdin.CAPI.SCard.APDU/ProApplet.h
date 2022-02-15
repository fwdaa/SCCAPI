#pragma once
#include "Applet.h"
#include "ProFormat.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Pro
{
    ///////////////////////////////////////////////////////////////////////////
	// Апплет eToken Pro
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
		protected: Applet(SCard::Card^ store, String^ name, int id, 
            PCSC::ReaderSession^ session, array<BYTE>^ atr) 
			
			// сохранить переданные параметры
			: LibApplet(store, name, id, session, atr) {}

        // конструктор
		protected: Applet(SCard::Card^ store, 
			PCSC::ReaderSession^ session, array<BYTE>^ atr) 
			
			// сохранить переданные параметры
			: LibApplet(store, "Pro", libapdu::TAppletPro, session, atr) {}

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

		// получить протокол аутентификации
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override; 
	};

    ///////////////////////////////////////////////////////////////////////////
	// Апплет eToken Pro Java
    ///////////////////////////////////////////////////////////////////////////
	ref class AppletJava : Applet
	{
        // конструктор
		public: static AppletJava^ Create(SCard::Card^ store,
			PCSC::ReaderSession^ session, array<BYTE>^ atr) 
		{
			// создать апплет
			AppletJava^ applet = gcnew AppletJava(store, session, atr); 

			// вернуть прокси
			try { return (AppletJava^)Proxy::SecurityObjectProxy::Create(applet); }

			// обработать возможную ошибку
			catch (Exception^) { delete applet; throw; } 
		}
        // конструктор
		protected: AppletJava(SCard::Card^ store, 
			PCSC::ReaderSession^ session, array<BYTE>^ atr) 
			
			// сохранить переданные параметры
			: Applet(store, "ProJava", libapdu::TAppletProJava, session, atr) {}

		// серийный номер смарт-карты
		public: virtual array<BYTE>^ GetSerial() override;  

        ///////////////////////////////////////////////////////////////////////
        // Аутентификация 
        ///////////////////////////////////////////////////////////////////////

		// признак наличия аутентификации администратора
		protected: virtual int HasAdminAuthentication() override; 

		// получить протокол аутентификации
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ protocolType) override; 
	};
}}}}}

