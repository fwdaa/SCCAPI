package aladdin.capi;
import aladdin.util.*; 
import aladdin.asn1.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////////
// Описание пользователя
///////////////////////////////////////////////////////////////////////////////
public class Principal implements java.security.Principal
{
    // конструктор
    public Principal(IEncodable encodable) 
    
        // сохранить переданные параметры
        { this.encodable = encodable; } private final IEncodable encodable; 
    
    // имя пользователя
    @Override public final String getName()
    {
        // шестнадцатеричное представление
        return Array.toHexString(encodable.encoded()); 
    }
    // хэш-код объекта
    @Override public final int hashCode() { return encodable.hashCode(); }
    
    // сравнить пользователей
    @Override public final boolean equals(Object another)
    {
        // проверить тип объекта
        if (!(another instanceof java.security.Principal)) return false; 
        
        // в зависимости от типа
        if (another instanceof Principal)
        {
            // сравнить пользователей
            return encodable.equals(((Principal)another).encodable); 
        }
        try { 
            // получить описание метода
            java.lang.reflect.Method method = another.getClass().getMethod("getEncoded");
            
            // получить бинарное представление
            byte[] encoded = (byte[])method.invoke(another); 
            
            // сравнить совпадение бинарных представлений
            return Arrays.equals(encodable.encoded(), encoded); 
        }
        // обработать возможную ошибку
        catch (Throwable e) { return false; }
    }
    // строковое представление
    @Override public final String toString() { return getName(); }
}
