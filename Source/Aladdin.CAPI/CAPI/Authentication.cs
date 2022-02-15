using System; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
    // Протокол аутентификации
	///////////////////////////////////////////////////////////////////////////
    public abstract class Authentication
    {
        // тип пользователя и тип аутентификации
        public abstract string User { get; } public abstract Type[] Types { get; }

        // выполнить аутентификацию
        public abstract Credentials[] Authenticate(SecurityObject obj); 
    }
}
