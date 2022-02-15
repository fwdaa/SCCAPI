#pragma once 
#include "AppletAuth.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Laser
{
	///////////////////////////////////////////////////////////////////////////
	// Сервис двухсторонней аутентификации апплета Laser для администратора
	///////////////////////////////////////////////////////////////////////////
	public ref class LibResponseService : LibPinService
    {
        // конструктор
		public: LibResponseService(LibApplet^ applet) 
			
			// сохранить переданные параметры
			: LibPinService(applet, "ADMIN", true) {}

        // установить пароль
        public: virtual void SetPassword(String^ pinCode) override; 

		// изменить пароль 
		public: virtual void ChangePassword(String^ pinCode) override;
    }; 
    ///////////////////////////////////////////////////////////////////////////
	// Тикет биометрической аутентификации
    ///////////////////////////////////////////////////////////////////////////
	public ref class LibBiometricTicket : Bio::MatchTemplate
	{
        // данные биометрической аутентификации
		private: array<BYTE>^ ticketData; private: libapdu::enumAuthMethod loginType;
        
        // конструктор
		public: LibBiometricTicket(Bio::MatchTemplate^ matchTemplate, 
			libapdu::enumAuthMethod loginType, array<BYTE>^ ticketData) 

			// сохранить переданные параметры
			: Bio::MatchTemplate(matchTemplate->Finger, matchTemplate->ValidationData)
		{	
            // проверить корректность данных
            if (ticketData->Length > 20) throw gcnew ArgumentException(); 

            // сохранить переданные параметры
			this->ticketData = ticketData; this->loginType = loginType;
		}
        // получить текстовое представление тикета
		public: String^ GetEncoded(String^ pinCode); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Сервис биометрической аутентификации апплета Laser для пользователя
	///////////////////////////////////////////////////////////////////////////
	public ref class BiometricService : Auth::BiometricService
    {
		// используемый провайдер
		private: static initonly Bio::Athena::Provider^ provider = gcnew Bio::Athena::Provider(); 

        // конструктор
		public: BiometricService(LibApplet^ applet, bool canLogin) 
			
			// сохранить переданные параметры
			: Auth::BiometricService(applet, "USER") 
		
			// сохранить переданные параметры
			{ this->canLogin = canLogin; } private: bool canLogin; 

		// возможность использования
		public: virtual property bool CanLogin { bool get() override 
		{ 
			// возможность использования
			return canLogin && Provider->EnumerateReaders()->Length > 0; 
		}}
		// возможность изменения
		public: virtual property bool CanChange { bool get() override 
		{ 
			// возможность изменения
			return Provider->EnumerateReaders()->Length > 0; 
		}}
		// информация сервиса аутентификации
		public: virtual AuthenticationInfo^ GetAuthenticationInfo() override; 

        // используемый провайдер
		public: property Bio::Provider^ Provider 
		{ 
			// используемый провайдер
			virtual Bio::Provider^ get() override { return provider; } 
		}
        // используемый уровнь FAR и качества отпечатков
        public: int GetFAR(); public: int GetImageQuality(); 

        // максимальное число отпечатков
        public: virtual int GetMaxAvailableFingers() override; 

        // используемые отпечатки
		public: virtual array<Bio::Finger>^ GetAvailableFingers() override;

		// создать шаблон для проверки отпечатка
		public: virtual Bio::MatchTemplate^ CreateTemplate(Bio::Finger finger, Bio::Image^ image) override; 

		// проверить соответствие отпечатка
		protected: virtual Bio::MatchTemplate^ MatchTemplate(Bio::MatchTemplate^ matchTemplate) override; 

        // установить отпечатки
		protected: virtual void EnrollTemplates(array<Bio::EnrollTemplate^>^ enrollTemplates) override; 
	}; 
}}}}}

