package aladdin.capi.auth;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Парольный протокол аутентификации
///////////////////////////////////////////////////////////////////////////
public class PasswordCredentials extends Credentials
{
    // тип пользователя и пароль
    private final String user; private final String password;

    // конструктор
    public PasswordCredentials(String user, String password)
    { 
        // проверить тип пользователя
        if (user == null) throw new IllegalArgumentException();
        
        // сохранить переданные параметы
        this.user = user; this.password = password; 
    } 
    // тип пользователя
    @Override public String user() { return user; }

    // используемый пароль
    public String password() { return password; }

    // выполнить аутентификацию
    @Override
    public Credentials[] authenticate(SecurityObject obj) throws IOException
    {
        // получить локальный объект аутентификации
        PasswordService service = (PasswordService)
            obj.getAuthenticationService(user, getClass());

        // проверить поддержку протокола
        if (service == null) throw new UnsupportedOperationException();

        // установить пароль пользователя
        return new Credentials[] { service.set(password) }; 
    }
} 
