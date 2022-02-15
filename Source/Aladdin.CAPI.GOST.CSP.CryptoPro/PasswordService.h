#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Сервис парольной аутентификации
	///////////////////////////////////////////////////////////////////////////
	public ref class PasswordService : CAPI::CSP::PasswordService
	{
		// конструктор
		public: PasswordService(SecurityObject^ obj, CAPI::CSP::Handle^ handle, bool canChange) 
			: CAPI::CSP::PasswordService(obj, handle) 
		
			// сохранить переданные параметры
			{ this->canChange = canChange; } private: bool canChange; 
        
        // возможность изменения 
		public: virtual property bool CanChange { bool get() override { return canChange; }}

		// указать аутентификационные данные
		protected: virtual void SetPassword(String^ password) override; 
		// изменить аутентификационные данные
		protected: virtual void ChangePassword(String^ password) override; 
	}; 
}}}}}
