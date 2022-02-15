package aladdin.capi;
import java.lang.reflect.*;

///////////////////////////////////////////////////////////////////////////
// Учетные данные аутентификации
///////////////////////////////////////////////////////////////////////////
public abstract class Credentials extends Authentication 
{
    // тип аутентификации
    @SuppressWarnings({"unchecked"}) 
    @Override public final Class<? extends Credentials>[] types()
    {
        // создать массив
        Object array = Array.newInstance(Class.class, 1); 
        
        // указать поддерживаемую аутентификацию
        Array.set(array, 0, getClass()); 
        
        // вернуть созданный массив
        return (Class<? extends Credentials>[])array; 
    }
}
