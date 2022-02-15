namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Контейнер PKCS12 с имитовставкой
	///////////////////////////////////////////////////////////////////////////
    public interface IPfxAuthenticatedContainer
    {
        // фабрика алгоритмов и пароль проверки целостности
        Factory Factory { get; } string AuthenticationPassword { get; }

		// указать пароль проверки целостности
		void SetAuthenticationPassword(string password); 

        // изменить пароль проверки целостности
		void ChangeAuthenticationPassword(string password); 
    }
}
