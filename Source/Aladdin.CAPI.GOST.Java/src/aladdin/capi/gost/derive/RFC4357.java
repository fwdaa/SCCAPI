package aladdin.capi.gost.derive;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм диверсификации ключа
///////////////////////////////////////////////////////////////////////////
public class RFC4357 extends KeyDerive
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // блочный алгоритм шифрования
    private final IBlockCipher gost28147;
    
	// конструктор
	public RFC4357(IBlockCipher gost28147)
	{ 
		// сохранить переданные параметры
		this.gost28147 = RefObject.addRef(gost28147); 
    } 
    // освободить ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить ресурсы
        RefObject.release(gost28147); super.onClose();
    }
    // тип ключа
    @Override public SecretKeyFactory keyFactory() { return gost28147.keyFactory(); } 
    // размер используемых ключей
    @Override public final int[] keySizes() { return gost28147.keySizes(); }

	// наследовать ключ
	@Override public ISecretKey deriveKey(ISecretKey key, 
        byte[] ukm, SecretKeyFactory keyFactory, int deriveSize) throws IOException 
	{
        // указать размер генерируемого ключа
        if (deriveSize < 0) deriveSize = 32; 
        
		// проверить размер генерируемого ключа
		if (deriveSize != 32) throw new UnsupportedOperationException();
 
        // проверить корректность параметров
        if (ukm.length != 8) throw new IllegalArgumentException(); 

		// скопировать значение ключа
		byte[] value = key.value().clone(); 
        
        // выполнить 8 раз
        for (int i = 0; i < 8; i++)
        {
            // инициализировать синхропосылку
            int[] s = new int[2]; int mask = 1; byte[] iv = new byte[8]; 

            // вычислить синхропосылку
            for (int j = 0; j < 8; j++, mask <<= 1)
            {
                // извлечь часть ключа 
                int partKey = Convert.toInt32(value, j * 4, ENDIAN); 

                // изменить часть синхропосылки
                s[((mask & ukm[i]) != 0) ? 0 : 1] += partKey;
            }
            // переустановить синхропосылку
            Convert.fromInt32(s[0], ENDIAN, iv, 0); 
            Convert.fromInt32(s[1], ENDIAN, iv, 4); 
            
            // создать ключ шифрования ключа
            try (ISecretKey KEK = key.keyFactory().create(value))
            {
                // указать параметры шифрования
                CipherMode.CFB parameters = new CipherMode.CFB(iv, gost28147.blockSize()); 
                
                // создать режим CFB
                try (Cipher modeCFB = gost28147.createBlockMode(parameters))
                {
                    // зашифровать ключ
                    modeCFB.encrypt(KEK, PaddingMode.NONE, value, 0, value.length, value, 0);
                }
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
        // вернуть созданный ключ
		return keyFactory.create(value);
	}
}
