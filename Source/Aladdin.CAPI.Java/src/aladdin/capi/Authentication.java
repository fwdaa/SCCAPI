package aladdin.capi;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Аутентификация
///////////////////////////////////////////////////////////////////////////
public abstract class Authentication
{
    // имя пользователя
    public abstract String user(); 
    
    // тип аутентификации
    public abstract Class<? extends Credentials>[] types(); 

    // выполнить аутентификацию
    public abstract Credentials[] authenticate(SecurityObject obj) throws IOException; 
}
