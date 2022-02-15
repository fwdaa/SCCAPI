package aladdin.capi.ansi.keys;
import aladdin.capi.*;
import java.security.*;
import javax.crypto.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Ключ DESX
///////////////////////////////////////////////////////////////////////////
public class DESX extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new DESX(); 
        
    // конструктор
    private DESX() { super("DESX"); }
        
	// размер ключей
	@Override public final int[] keySizes() { return new int[] { 24 }; }
    
    // создать ключ
    @Override public ISecretKey create(byte[] value) 
    { 
        // создать копию значения
        value = value.clone(); 
            
        // выполнить нормализацию ключа
        DES.adjustParity(value, 0, 8); 
            
        // создать ключ
        return super.create(value); 
    }
    // сгенерировать ключ
    @Override public ISecretKey generate(IRand rand, int keySize) throws IOException
    {
        // проверить размер ключа
        if (!KeySizes.contains(keySizes(), keySize)) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException();
        } 
        // сгенерировать ключ
        byte[] value = new byte[keySize]; rand.generate(value, 0, keySize);

        // выполнить нормализацию ключа
        DES.adjustParity(value, 0, 8); 
        try { 
            // для слабого ключа
            while(DESKeySpec.isWeak(value, 0)) 
            {
                // сгенерировать ключ
                rand.generate(value, 0, 8);
                    
                // выполнить нормализацию ключа
                DES.adjustParity(value, 0, 8); 
            }
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }

        // вернуть сгенерированный ключ
        return new SecretKey(this, value); 
    }
}
