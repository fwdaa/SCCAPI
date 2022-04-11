package aladdin.capi;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма
///////////////////////////////////////////////////////////////////////////
public final class SecretKey implements ISecretKey 
{
    // номер версии для сериализации
    private static final long serialVersionUID = -8333279770898548442L;

    // конструктор
	public static ISecretKey fromPassword(String password, String charset) 
    { 
        // закодировать пароль
        try { byte[] encoded = password.getBytes(charset); 
        
            // создать объект ключа 
            return new SecretKey(SecretKeyFactory.GENERIC, encoded); 
        }
        // обработать неожидаемое исключение
        catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
    } 
    // тип и значение ключа
    private final SecretKeyFactory keyFactory; private final byte[] value;
    
    // конструктор
    public SecretKey(SecretKeyFactory keyFactory, byte[] value)
    {     
        // сохранить переданные параметры
        this.keyFactory = keyFactory; this.value = value; 
    }
    // размер ключа
    @Override public final SecretKeyFactory keyFactory() { return keyFactory; }
    // размер ключа
    @Override public final int length() { return value.length; }
    // значение ключа
    @Override public final byte[] value() { return value; } 

    // увеличить/уменьшить счетчик ссылок
    @Override public final void addRef () {} 
    @Override public final void release() {} 
        
    // уменьшить счетчик ссылок
    @Override public final void close() { release(); }
}
