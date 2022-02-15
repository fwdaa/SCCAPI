using System;
using System.Collections.Generic;

namespace Aladdin.CAPI.Auth
{
    ///////////////////////////////////////////////////////////////////////
    // Выбор фиксированной парольной аутентификации
    ///////////////////////////////////////////////////////////////////////
    public class PasswordSelector : AuthenticationSelector
    {
        // конструктор
        public PasswordSelector(string user, string password) : base(user)

        // сохранить переданные параметры
            { this.password = password; } private string password;

        // получить требуемую аутентификацию
        protected override Authentication[] GetAuthentications(
            SecurityObject obj, List<Type> authenticationTypes)
        {
            // проверить наличие парольной аутентификации
            if (authenticationTypes.Contains(typeof(PasswordCredentials)))
            {
                // указать пароль аутентификации
                Authentication authentication = new PasswordCredentials(User, password);

                // вернуть требуемую аутентификацию
                return new Authentication[] { authentication };
            }
            // вызвать базовую функцию
            return base.GetAuthentications(obj, authenticationTypes);
        }
    }
}
