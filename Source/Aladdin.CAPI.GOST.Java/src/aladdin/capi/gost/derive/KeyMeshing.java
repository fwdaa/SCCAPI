package aladdin.capi.gost.derive;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм смены ключа RFC4357
///////////////////////////////////////////////////////////////////////////////
public class KeyMeshing extends KeyDerive
{   
    // алгоритм шифрования блока
    private final Cipher gost28147; 
    
    // конструктор
    public KeyMeshing(Cipher gost28147) 
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

	// наследовать ключ
	@Override public ISecretKey deriveKey(ISecretKey key, 
        byte[] iv, SecretKeyFactory keyFactory, int deriveSize) 
            throws IOException, InvalidKeyException
    {
        // указать размер генерируемого ключа
        if (deriveSize < 0) deriveSize = 32; 
        
        // проверить размер ключа
        if (deriveSize != 32) throw new UnsupportedOperationException(); 
        
    	// константа для расшифрования
		byte[] C = {
			(byte)0x69, (byte)0x00, (byte)0x72, (byte)0x22, 
            (byte)0x64, (byte)0xC9, (byte)0x04, (byte)0x23,
			(byte)0x8D, (byte)0x3A, (byte)0xDB, (byte)0x96, 
            (byte)0x46, (byte)0xE9, (byte)0x2A, (byte)0xC4,
			(byte)0x18, (byte)0xFE, (byte)0xAC, (byte)0x94, 
            (byte)0x00, (byte)0xED, (byte)0x07, (byte)0x12,
			(byte)0xC0, (byte)0x86, (byte)0xDC, (byte)0xC2, 
            (byte)0xEF, (byte)0x4C, (byte)0xA9, (byte)0x2B,
		};
		// выделить память для нового ключа
		byte[] value = new byte[deriveSize]; 

        // переустановить ключ
        gost28147.decrypt(key, PaddingMode.NONE, C, 0, C.length, value, 0);
            
        // создать ключ
        try (ISecretKey newKey = keyFactory.create(value)) 
        {
            // зашифровать синхропосылку
            if (iv != null) gost28147.encrypt(newKey, PaddingMode.NONE, iv, 0, iv.length, iv, 0); 

            // увеличить счетчик ссылок
            return RefObject.addRef(newKey);  
        }
    }
}
