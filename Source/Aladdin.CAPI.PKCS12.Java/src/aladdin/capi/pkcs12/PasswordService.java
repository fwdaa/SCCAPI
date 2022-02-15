package aladdin.capi.pkcs12;
import aladdin.capi.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Сервис аутентификации
///////////////////////////////////////////////////////////////////////////
public class PasswordService extends aladdin.capi.auth.PasswordService
{
    // содержимое контейнера
    private final PfxEncryptedContainer container; 

    // конструктор
    public PasswordService(Container obj, PfxEncryptedContainer container) 
    {     
        // сохранить переданные параметры
        super(obj, "USER"); this.container = container; 
    } 
    // возможность изменения 
    @Override public boolean canChange() { return true; }

    // информация аутентификации объекта
    @Override public AuthenticationInfo getAuthenticationInfo()
    {
        // информация аутентификации объекта
        return new AuthenticationInfo(AuthenticationInfo.UNLIMITED_ATTEMPTS); 
    }
    // указать пароль контейнера
    @Override protected void setPassword(String password) throws IOException
    {
        // проверить тип контейнера
        if (container instanceof PfxAuthenticatedEncryptedContainer)
        {
            // выполнить преобразование типа
            PfxAuthenticatedEncryptedContainer obj = 
                (PfxAuthenticatedEncryptedContainer)container; 
            
            // указать пароль контейнера
            obj.setPassword(password);
        }
        else {
            // указать используемый ключ
            ISecretKey key = SecretKey.fromPassword(password, "UTF-8");  
        
            // расшифровать контейнер
            container.setEncryptionKey(key);
        }
    }
    // изменить пароль контейнера
    @Override protected void changePassword(String password) throws IOException
    {
        // выполнить аутентификацию
        ((Container)target()).authenticate(); 

        // проверить тип контейнера
        if (container instanceof PfxAuthenticatedEncryptedContainer)
        {
            // выполнить преобразование типа
            PfxAuthenticatedEncryptedContainer obj = 
                (PfxAuthenticatedEncryptedContainer)container; 
            
            // изменить пароль
           obj.changePassword(password); 
        }
        else { 
            // указать используемый ключ
            ISecretKey key = SecretKey.fromPassword(password, "UTF-8");  
            
            // переустановить ключ
            container.changeEncryptionKey(key); 
        }
        // перезаписать контейнер на диске
        ((Container)target()).flush(); 
    }
}
