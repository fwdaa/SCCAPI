package aladdin.capi;

///////////////////////////////////////////////////////////////////////////
// Сервис аутентификации объекта
///////////////////////////////////////////////////////////////////////////
public class AuthenticationService
{
    // объект и тип пользователя
    private final SecurityObject target; private final String user; 
    
    // конструктор
    public AuthenticationService(SecurityObject target, String user)
    { 
        // сохранить переданные параметры
        this.target = target; this.user = user; 
    } 
    // целевой объект
    public final SecurityObject target() { return target; }  
    // тип пользователя
    public final String user() { return user; }  
    
    // возможность использования
    public boolean canLogin()  { return true;  }
    // возможность изменения 
    public boolean canChange() { return false; }
        
    // информация аутентификации объекта 
    public AuthenticationInfo getAuthenticationInfo()
    {
        // информация аутентификации объекта 
        return new AuthenticationInfo(AuthenticationInfo.UNKNOWN_ATTEMPTS); 
    }
}
