package aladdin.capi.gost.derive;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*; 
import java.security.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм смены ключа ACPKM
///////////////////////////////////////////////////////////////////////////////
public class ACPKM extends KeyDerive
{
    // алгоритм шифрования блока
    private final Cipher cipher;

    // конструктор
    public ACPKM(Cipher cipher)
    { 
        // сохранить переданные параметры
        this.cipher = RefObject.addRef(cipher); 
    }  
    // освободить ресурсы
    @Override protected void onClose() throws IOException  
    { 
        // освободить ресурсы
        RefObject.release(cipher); super.onClose();
    }
    // тип ключа
    @Override public SecretKeyFactory keyFactory() { return cipher.keyFactory(); } 

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
	    byte[] D = new byte[] {
		    (byte)0x80, (byte)0x81, (byte)0x82, (byte)0x83, 
            (byte)0x84, (byte)0x85, (byte)0x86, (byte)0x87,
		    (byte)0x88, (byte)0x89, (byte)0x8A, (byte)0x8B, 
            (byte)0x8C, (byte)0x8D, (byte)0x8E, (byte)0x8F,
		    (byte)0x90, (byte)0x91, (byte)0x92, (byte)0x93, 
            (byte)0x94, (byte)0x95, (byte)0x96, (byte)0x97,
		    (byte)0x98, (byte)0x99, (byte)0x9A, (byte)0x9B, 
            (byte)0x9C, (byte)0x9D, (byte)0x9E, (byte)0x9F,
	    };
	    // выделить память для нового ключа
	    byte[] value = new byte[deriveSize]; 

        // сгенерировать новый ключ
	    cipher.encrypt(key, PaddingMode.NONE, D, 0, D.length, value, 0);

        // создать ключ
        return keyFactory.create(value);  
    }
}
