package aladdin.capi.retro.javax.crypto.spec;
import aladdin.capi.retro.javax.crypto.*;
import java.security.spec.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Симметричный ключ
///////////////////////////////////////////////////////////////////////////////
public class SecretKeySpec implements KeySpec, SecretKey 
{
    // номер версии для сериализации
    private static final long serialVersionUID = 6577238317307289933L;
    
    // имя алгоритма и значение ключа
    private final String algorithm; private final byte[] key; 

    // конструктор
    public SecretKeySpec(byte[] key, String algorithm) 
    {
        // сохранить переданные параметры
        this.key = (byte[])key.clone(); this.algorithm = algorithm; 
    }
    public SecretKeySpec(byte[] key, int offset, int len, String algorithm) 
    {
        // выделить память для значения
        this.key = new byte[len]; this.algorithm = algorithm; 
        
        // сохранить переданные параметры
        System.arraycopy(key, offset, this.key, 0, len); 
    }
    // имя алгоритма
    public String getAlgorithm() { return algorithm; }
    // формат значения 
    public String getFormat() { return "RAW"; } 
    // значение ключа
    public byte[] getEncoded() { return (byte[])key.clone(); }

    public boolean equals(Object obj) 
    {
        // проверить совпадение ссылок
        if (this == obj) return true; if (obj == null) return false; 
        
        // проверить тип объекта
        if (!(obj instanceof SecretKeySpec)) return false; 
        
        // определить имя алгоритма
        String thatAlg = ((SecretKey)obj).getAlgorithm();
        
        // при несовпадении имени алгоритма
        if (!(thatAlg.equalsIgnoreCase(algorithm))) 
        {
            // проверить совпадение альтернативных имен
            if (algorithm.equalsIgnoreCase("TripleDES") && 
                thatAlg  .equalsIgnoreCase("DESede")) {} else 
            
            // проверить совпадение альтернативных имен
            if (thatAlg  .equalsIgnoreCase("TripleDES") && 
                algorithm.equalsIgnoreCase("DESede")) {} else 
                
            return false;
        }
        // получить значение ключа
        byte[] thatKey = ((SecretKey)obj).getEncoded();

        // проверить совпадение значений
        return Arrays.equals(key, thatKey);    
    }
    public int hashCode() 
    {
        // вычислить хэш-значение ключа
        int retval = 0; for (int i = 1; i < key.length; i++) retval += key[i] * i;
        
        // обработать специальное имя алгоритма
        if (algorithm.equalsIgnoreCase("TripleDES")) return (retval ^= "desede".hashCode());
        
        // вернуть хэш-значение ключа
        return (retval ^= algorithm.toLowerCase(Locale.ENGLISH).hashCode());    
    }
}
