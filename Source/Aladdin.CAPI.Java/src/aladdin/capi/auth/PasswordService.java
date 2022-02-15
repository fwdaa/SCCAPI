package aladdin.capi.auth;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Сервис парольной аутентификации
///////////////////////////////////////////////////////////////////////////
public abstract class PasswordService extends AuthenticationService
{
    // конструктор
    public PasswordService(SecurityObject obj, String user) { super(obj, user); }
    
    // установить пароль
	public final Credentials set(String password) throws IOException
    {
        // установить пароль
        setPassword(password); String provider = target().provider().name(); 
        
        // указать тип аутентификации
        Credentials credentials = new PasswordCredentials(user(), password); 
        
        // получить кэш аутентификации
        CredentialsManager cache = ExecutionContext.getProviderCache(provider); 
        
        // добавить данные в кэш
        cache.setData(target().info(), user(), credentials); return credentials; 
    }
    // установить пароль
	protected void setPassword(String password) throws IOException
    {
        // операция не поддерживается
        throw new UnsupportedOperationException(); 
    }
	// изменить пароль
	public final Credentials change(String password) throws IOException
    {
        // изменить пароль
        changePassword(password); String provider = target().provider().name(); 
        
        // указать тип аутентификации
        Credentials credentials = new PasswordCredentials(user(), password); 
        
        // получить кэш аутентификации
        CredentialsManager cache = ExecutionContext.getProviderCache(provider); 
            
        // удалить данные из кэша
        cache.clearData(target().info(), user(), credentials.getClass()); return credentials; 
    }
	// изменить пароль
	protected void changePassword(String password) throws IOException
    {
        // операция не поддерживается
        throw new UnsupportedOperationException(); 
    }
}
