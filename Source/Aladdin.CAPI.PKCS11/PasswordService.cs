using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Сервис парольной аутентификации
    ///////////////////////////////////////////////////////////////////////////
    public class PasswordService : Auth.PasswordService
    {
	    // конструктор
	    public PasswordService(Applet applet, string user) : base(applet, user) {}

        // возможность аутентификации
	    public override bool CanLogin { get 
        { 
            // проверить тип аутентификации
            if (String.Compare(User, "ADMIN", true) == 0) return true; 
            try {
                // получить информацию смарт-карты
                TokenInfo info = ((Applet)Target).GetInfo(); 
            
                // проверить наличие аутентификации пользователя
                return ((info.Flags & API.CKF_USER_PIN_INITIALIZED) != 0); 
            }
            // обработать возможную ошибку
            catch { return false; }
	    }}
        // возможность изменения 
        public override bool CanChange { get { return true; }}

	    // установить аутентификационные данные
	    protected override void SetPassword(string password)
	    {
            if (String.Compare(User, "ADMIN", true) != 0)
            {
                // создать сеанс
                using (Session session = ((Applet)Target).OpenSession(API.CKS_RO_PUBLIC_SESSION))
                {
                    // выполнить аутентификацию пользователя
                    session.Login(API.CKU_USER, password); 
                }
            }
            else {
                // создать сеанс
                using (Session session = ((Applet)Target).OpenSession(API.CKS_RW_PUBLIC_SESSION))
                {
                    // получить состояние сеанса
                    ulong state = session.GetSessionInfo().State; 
                    
                    // отменить аутентификацию адиминистратора
                    if (state == API.CKS_RW_USER_FUNCTIONS) session.Logout();
                    
                    // выполнить аутентификацию администратора
                    session.Login(API.CKU_SO, password); 
                }
            }
	    }
	    // изменить аутентификационные данные
	    protected override void ChangePassword(String password)
	    {
            if (String.Compare(User, "ADMIN", true) != 0)
            {
                // создать сеанс
                using (Session session = ((Applet)Target).OpenSession(API.CKS_RW_PUBLIC_SESSION)) 
                {
                    // получить состояние сеанса
                    ulong state = session.GetSessionInfo().State; 
                    
                    // при наличии аутентификации администратора
                    if (state == API.CKS_RW_SO_FUNCTIONS) 
                    {
                        // установить пароль пользователя
                        session.SetUserPassword(password); 
                    }
                }
            }
            // выполнить аутентификацию
            Applet applet = (Applet)Target; applet.Authenticate(); 
            
            // получить кэш аутентификации
            CredentialsManager cache = ExecutionContext.GetProviderCache(applet.Provider.Name); 
                
            // получить аутентификацию пользователя
            Auth.PasswordCredentials credentials = (Auth.PasswordCredentials)
                cache.GetData(applet.Info, User, typeof(Auth.PasswordCredentials)); 

            // создать сеанс
            using (Session session = applet.OpenSession(API.CKS_RW_PUBLIC_SESSION)) 
            {
                // получить состояние сеанса
                ulong state = session.GetSessionInfo().State; 
                    
                // при аутентификации пользователя
		        if (String.Compare(User, "ADMIN", true) != 0)
		        {
			        // при наличии аутентификации администратора
			        if (state == API.CKS_RW_SO_FUNCTIONS) 
			        {
				        // установить пароль пользователя
				        session.SetUserPassword(password); return; 
			        }
			        // проверить наличие аутентификации
			        if (credentials == null) throw new InvalidOperationException(); 

                    // при отсутствии аутентификации пользователя
                    if (state != API.CKS_RW_USER_FUNCTIONS)
                    {
                        // выполнить аутентификацию пользователя
                        session.Login(API.CKU_USER, credentials.Password);
                    }
		        }
		        else {
			        // проверить наличие аутентификации
			        if (credentials == null) throw new InvalidOperationException(); 

			        // сбросить аутентификацию пользователя
			        if (state == API.CKS_RW_USER_FUNCTIONS) session.Logout(); 

                    // при отсутствии аутентификации администратора
                    if (state != API.CKS_RW_SO_FUNCTIONS)
                    {
                        // выполнить аутентификацию администратора
                        session.Login(API.CKU_SO, credentials.Password);
                    }
                }
                // переустановить пароль
                session.ChangePassword(credentials.Password, password); 
            }
	    }
    }
}
