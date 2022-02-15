using System; 

namespace Aladdin.CAPI.Auth
{
    ///////////////////////////////////////////////////////////////////////////
    // Сервис парольной аутентификации
    ///////////////////////////////////////////////////////////////////////////
    public abstract class PasswordService : AuthenticationService
    {
        // конструктор
        public PasswordService(SecurityObject obj, string user) : base(obj, user) {}

		// установить пароль
		public Credentials Set(string password)
        {
            // установить пароль
            SetPassword(password); string provider = Target.Provider.Name; 
        
            // указать тип аутентификации
            Credentials credentials = new PasswordCredentials(User, password); 

            // получить кэш аутентификации
            CredentialsManager cache = ExecutionContext.GetProviderCache(provider); 
                
            // добавить данные в кэш
            cache.SetData(Target.Info, User, credentials); return credentials; 
        }
		// установить пароль
		protected virtual void SetPassword(string password)
        {
            // операция не поддерживается
            throw new NotSupportedException(); 
        }
		// изменить пароль
		public Credentials Change(string password)
        {
            // изменить пароль
            ChangePassword(password); string provider = Target.Provider.Name; 

            // указать тип аутентификации
            Credentials credentials = new PasswordCredentials(User, password);

            // получить кэш аутентификации
            CredentialsManager cache = ExecutionContext.GetProviderCache(provider); 

            // удалить старые данные из кэша
            cache.ClearData(Target.Info, User, credentials.GetType()); return credentials; 
        }
		// изменить пароль
		protected virtual void ChangePassword(string password)
        {
            // операция не поддерживается
            throw new NotSupportedException(); 
        }
    }
}
