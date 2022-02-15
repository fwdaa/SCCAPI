package aladdin.capi.pkcs11;
import aladdin.capi.*;
import aladdin.capi.auth.*;
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Аутентификация устройства
///////////////////////////////////////////////////////////////////////////
 public class PasswordService extends aladdin.capi.auth.PasswordService
{
    // конструктор
    public PasswordService(Applet applet, String user) { super(applet, user); }
    
    // возможность аутентификации
    @Override public boolean canLogin() 
    { 
        // проверить тип аутентификации
        if (user().equalsIgnoreCase("ADMIN")) return true; 
        try {
            // получить информацию смарт-карты
            TokenInfo info = ((Applet)target()).getInfo(); 
            
            // проверить наличие аутентификации пользователя
            return ((info.flags() & API.CKF_USER_PIN_INITIALIZED) != 0); 
        }
        // обработать возможную ошибку
        catch (Throwable e) { return false; }
    }
    // возможность изменения 
    @Override public boolean canChange() { return true; }

    // установить аутентификационные данные
    @Override protected void setPassword(String password) throws IOException
    {
        if (!user().equalsIgnoreCase("ADMIN"))
        {
            // создать сеанс
            try (Session session = ((Applet)target()).openSession(API.CKS_RO_PUBLIC_SESSION))
            {
                // выполнить аутентификацию пользователя
                session.login(API.CKU_USER, password); 
            }
        }
        else {
            // создать сеанс
            try (Session session = ((Applet)target()).openSession(API.CKS_RW_PUBLIC_SESSION))
            {
                // получить состояние сеанса
                long state = session.getSessionInfo().state(); 
                    
                // отменить аутентификацию адиминистратора
                if (state == API.CKS_RW_USER_FUNCTIONS) session.logout();
                    
                // выполнить аутентификацию администратора
                session.login(API.CKU_SO, password); 
            }
        }
    }
    // изменить аутентификационные данные
    @Override protected void changePassword(String password) throws IOException
    {
        if (!user().equalsIgnoreCase("ADMIN"))
        {
            // создать сеанс
            try (Session session = ((Applet)target()).openSession(API.CKS_RW_PUBLIC_SESSION))
            {
                // получить состояние сеанса
                long state = session.getSessionInfo().state(); 
                    
                // при наличии аутентификации администратора
                if (state == API.CKS_RW_SO_FUNCTIONS) 
                {
                    // установить пароль пользователя
                    session.setUserPassword(password); 
                }
            }
        }
        // выполнить аутентификацию
        Applet applet = (Applet)target(); applet.authenticate(); 
            
        // получить кэш аутентификации
        CredentialsManager cache = ExecutionContext.getProviderCache(applet.provider().name()); 
        
        // получить аутентификацию пользователя
        PasswordCredentials credentials = (PasswordCredentials)
            cache.getData(applet.info(), user(), PasswordCredentials.class); 
                
        // создать сеанс
        try (Session session = applet.openSession(API.CKS_RW_PUBLIC_SESSION))
        {
            // получить состояние сеанса
            long state = session.getSessionInfo().state(); 
                    
            if (!user().equalsIgnoreCase("ADMIN"))
            {
                // при наличии аутентификации администратора
                if (state == API.CKS_RW_SO_FUNCTIONS) 
                {
                    // установить пароль пользователя
                    session.setUserPassword(credentials.password()); return; 
                }
                // проверить наличие аутентификации
                if (credentials == null) throw new IllegalStateException(); 
                    
                // при отсутствии аутентификации пользователя
                if (state != API.CKS_RW_USER_FUNCTIONS)
                {
                    // выполнить аутентификацию пользователя
                    session.login(API.CKU_USER, credentials.password());
                }
            }
            else {
                // проверить наличие аутентификации
                if (credentials == null) throw new IllegalStateException(); 
                
                // сбросить аутентификацию пользователя
                if (state == API.CKS_RW_USER_FUNCTIONS) session.logout();
                
                // при отсутствии аутентификации администратора
                if (state != API.CKS_RW_SO_FUNCTIONS)
                {
                    // выполнить аутентификацию администратора
                    session.login(API.CKU_SO, credentials.password());
                }
            }
            // переустановить пароль
            session.changePassword(credentials.password(), password); 
        }
    }
} 
