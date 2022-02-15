using System;

namespace Aladdin.CAPI.Auth
{
	///////////////////////////////////////////////////////////////////////////
	// Парольный протокол аутентификации
	///////////////////////////////////////////////////////////////////////////
	public class PasswordCredentials : Credentials
	{
        // тип пользователя и пароль
        private string user; private string password;

        // конструктор
        public PasswordCredentials(string user, string password)
        { 
            // проверить тип пользователя
            if (user == null) throw new ArgumentException();

            // сохранить переданные параметы
            this.user = user; this.password = password; 
        } 
        // тип пользователя
        public override string User { get { return user; }}

        // используемый пароль
        public string Password { get { return password; }}

        // выполнить аутентификацию
        public override Credentials[] Authenticate(SecurityObject obj)
        {
            // получить локальный объект аутентификации
            PasswordService service = (PasswordService)
                obj.GetAuthenticationService(user, GetType());

            // проверить поддержку протокола
            if (service == null) throw new NotSupportedException();

            // установить пароль пользователя
            return new Credentials[] { service.Set(password) }; 
        }
    } 
}
