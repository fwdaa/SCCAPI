package aladdin.capi.retro.javax.crypto.spec;
import java.security.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Ключ DES
///////////////////////////////////////////////////////////////////////////////
public class DESKeySpec implements KeySpec 
{
    // размер ключа DES
    public static final int DES_KEY_LEN = 8;

    // значение ключа
    private final byte[] key;

    /*
     * Weak/semi-weak keys copied from FIPS 74.
     *
     * "...The first 6 keys have duals different than themselves, hence
     * each is both a key and a dual giving 12 keys with duals. The last
     * four keys equal their duals, and are called self-dual keys..."
     *
     * 1.   E001E001F101F101    01E001E001F101F1
     * 2.   FE1FFE1FFEOEFEOE    1FFE1FFEOEFEOEFE
     * 3.   E01FE01FF10EF10E    1FE01FEOOEF10EF1
     * 4.   01FE01FE01FE01FE    FE01FE01FE01FE01
     * 5.   011F011F010E010E    1F011F010E010E01
     * 6.   E0FEE0FEF1FEF1FE    FEE0FEE0FEF1FEF1
     * 7.   0101010101010101    0101010101010101
     * 8.   FEFEFEFEFEFEFEFE    FEFEFEFEFEFEFEFE
     * 9.   E0E0E0E0F1F1F1F1    E0E0E0E0F1F1F1F1
     * 10.  1F1F1F1F0E0E0E0E    1F1F1F1F0E0E0E0E
     */
    private static final byte[][] WEAK_KEYS = 
    {
        { (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01,
          (byte)0x01, (byte)0x01, (byte)0x01 },

        { (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE,
          (byte)0xFE, (byte)0xFE, (byte)0xFE },

        { (byte)0x1F, (byte)0x1F, (byte)0x1F, (byte)0x1F, (byte)0x0E,
          (byte)0x0E, (byte)0x0E, (byte)0x0E },

        { (byte)0xE0, (byte)0xE0, (byte)0xE0, (byte)0xE0, (byte)0xF1,
          (byte)0xF1, (byte)0xF1, (byte)0xF1 },

        { (byte)0x01, (byte)0xFE, (byte)0x01, (byte)0xFE, (byte)0x01,
          (byte)0xFE, (byte)0x01, (byte)0xFE },

        { (byte)0x1F, (byte)0xE0, (byte)0x1F, (byte)0xE0, (byte)0x0E,
          (byte)0xF1, (byte)0x0E, (byte)0xF1 },

        { (byte)0x01, (byte)0xE0, (byte)0x01, (byte)0xE0, (byte)0x01,
          (byte)0xF1, (byte)0x01, (byte)0xF1 },

        { (byte)0x1F, (byte)0xFE, (byte)0x1F, (byte)0xFE, (byte)0x0E,
          (byte)0xFE, (byte)0x0E, (byte)0xFE },

        { (byte)0x01, (byte)0x1F, (byte)0x01, (byte)0x1F, (byte)0x01,
          (byte)0x0E, (byte)0x01, (byte)0x0E },

        { (byte)0xE0, (byte)0xFE, (byte)0xE0, (byte)0xFE, (byte)0xF1,
          (byte)0xFE, (byte)0xF1, (byte)0xFE },

        { (byte)0xFE, (byte)0x01, (byte)0xFE, (byte)0x01, (byte)0xFE,
          (byte)0x01, (byte)0xFE, (byte)0x01 },

        { (byte)0xE0, (byte)0x1F, (byte)0xE0, (byte)0x1F, (byte)0xF1,
          (byte)0x0E, (byte)0xF1, (byte)0x0E },

        { (byte)0xE0, (byte)0x01, (byte)0xE0, (byte)0x01, (byte)0xF1,
          (byte)0x01, (byte)0xF1, (byte)0x01 },

        { (byte)0xFE, (byte)0x1F, (byte)0xFE, (byte)0x1F, (byte)0xFE,
          (byte)0x0E, (byte)0xFE, (byte)0x0E },

        { (byte)0x1F, (byte)0x01, (byte)0x1F, (byte)0x01, (byte)0x0E,
          (byte)0x01, (byte)0x0E, (byte)0x01 },

        { (byte)0xFE, (byte)0xE0, (byte)0xFE, (byte)0xE0, (byte)0xFE,
          (byte)0xF1, (byte)0xFE, (byte)0xF1 }
    };
    // конструктор
    public DESKeySpec(byte[] key) throws InvalidKeyException { this(key, 0); }
    
    // конструктор
    public DESKeySpec(byte[] key, int offset) throws InvalidKeyException 
    {
        // проверить размер буфера
        if (key.length - offset < DES_KEY_LEN) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException("Wrong key size");
        }
        // выделить память для ключа
        this.key = new byte[DES_KEY_LEN];
        
        // скопировать значение ключа
        System.arraycopy(key, offset, this.key, 0, DES_KEY_LEN);
    }
    // значение ключа
    public byte[] getKey() { return (byte[])key.clone(); }

    // проверить четность ключа
    public static boolean isParityAdjusted(byte[] key, int offset)
        throws InvalidKeyException 
    {
        // проверить наличие ключа
        if (key == null) throw new InvalidKeyException("null key");
            
        // проверить размер буфера
        if (key.length - offset < DES_KEY_LEN) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException("Wrong key size");
        }
        // для всех байтов ключа
        for (int i = 0; i < DES_KEY_LEN; i++, offset++) 
        {
            // для вех битов
            int k = 0; for (int j = 0; j < 8; j++)
            {
                // определить число установленных битов
                if ((key[offset] & (0x1 << j)) != 0) k++;
            }
            // проверить нечетное число установленных битов
            if ((k & 1) == 0) return false;
        }
        return true;
    }
    // проверить слабость ключа
    public static boolean isWeak(byte[] key, int offset)
        throws InvalidKeyException 
    {
        if (key == null) throw new InvalidKeyException("null key");
        
        // проверить размер буфера
        if (key.length - offset < DES_KEY_LEN) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException("Wrong key size");
        }
        // для всех слабых и полуслабых ключей
        for (int i = 0; i < WEAK_KEYS.length; i++) 
        {
            boolean found = true;
            
            // для всех байтов ключа
            for (int j = 0; j < DES_KEY_LEN && found == true; j++) 
            {
                // проверить слабое значение байта
                if (WEAK_KEYS[i][j] != key[offset + j]) found = false;
            }
            // проверить слабое значение ключа
            if (found == true) return found;
        }
        return false;
    }
}
