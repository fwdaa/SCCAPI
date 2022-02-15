package aladdin.capi.retro.javax.crypto.spec;
import java.security.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Ключ TDES
///////////////////////////////////////////////////////////////////////////////
public class DESedeKeySpec implements KeySpec 
{
    // размер ключа
    public static final int DES_EDE_KEY_LEN = 24;

    // значение ключа
    private final byte[] key;

    // конструктор
    public DESedeKeySpec(byte[] key) throws InvalidKeyException { this(key, 0); }

    // конструктор
    public DESedeKeySpec(byte[] key, int offset) throws InvalidKeyException 
    {
        // проверить размер буфера
        if (key.length - offset < DES_EDE_KEY_LEN) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException("Wrong key size");
        }
        // выделить память для ключа
        this.key = new byte[DES_EDE_KEY_LEN];
        
        // скопировать значение ключа
        System.arraycopy(key, offset, this.key, 0, 24);
    }
    // значение ключа
    public byte[] getKey() { return (byte[])key.clone(); }

    // проверить четность ключа
    public static boolean isParityAdjusted(byte[] key, int offset)
        throws InvalidKeyException 
    {
        // проверить размер буфера
        if (key.length - offset < DES_EDE_KEY_LEN) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException("Wrong key size");
        }
        // проверить четность ключа
        if (!DESKeySpec.isParityAdjusted(key, offset    ) || 
            !DESKeySpec.isParityAdjusted(key, offset + 8) ||
            !DESKeySpec.isParityAdjusted(key, offset + 16)) return false;
        
        return true; 
    }
}
