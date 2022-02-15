using System;

namespace Aladdin.CAPI.Auth
{
	///////////////////////////////////////////////////////////////////////////
	// Биометрический протокол аутентификации
	///////////////////////////////////////////////////////////////////////////
	public class BiometricCredentials : Credentials
    {
        // тип пользователя и данные отпечатка
        private string user; private Bio.MatchTemplate matchTemplate;

        // конструктор
        public BiometricCredentials(string user, Bio.MatchTemplate matchTemplate)
        { 
            // проверить тип пользователя
            if (user == null) throw new ArgumentException();

            // сохранить переданные параметры
            this.user = user; this.matchTemplate = matchTemplate; 
        } 
        // тип пользователя
        public override string User { get { return user; }}

        // данные отпечатка
        public Bio.MatchTemplate MatchTemplate { get { return matchTemplate; }} 

        // выполнить аутентификацию
        public override Credentials[] Authenticate(SecurityObject obj)
        {
            // получить локальный объект аутентификации
            BiometricService service = (BiometricService)
                obj.GetAuthenticationService(user, GetType());

            // проверить поддержку протокола
            if (service == null) throw new NotSupportedException();

            // проверить соответствие отпечатка
            return new Credentials[] { service.Match(matchTemplate) }; 
        }
	} 
}
