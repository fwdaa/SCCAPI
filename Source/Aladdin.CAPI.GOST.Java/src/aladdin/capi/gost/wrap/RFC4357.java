package aladdin.capi.gost.wrap;
import aladdin.capi.gost.engine.*;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.capi.derive.*;
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////
public class RFC4357 extends aladdin.capi.KeyWrap
{
    // флаги алгоритмов шифрования ключа
    public static final int NONE_SBOX_A = 0x0001; 
    public static final int NONE_SBOX_B = 0x0002; 
    public static final int NONE_SBOX_C = 0x0004; 
    public static final int NONE_SBOX_D = 0x0008; 
    public static final int NONE_SBOX_Z = 0x0100; 
    public static final int CPRO_SBOX_A = 0x0010; 
    public static final int CPRO_SBOX_B = 0x0020; 
    public static final int CPRO_SBOX_C = 0x0040; 
    public static final int CPRO_SBOX_D = 0x0080; 
    public static final int CPRO_SBOX_Z = 0x0200; 
    
    // алгоритмы шифрования и выработки имитовставки
    private final Cipher cipher; private final Mac macAlgorithm;
    // алгоритм диверсификации и случайные данные
    private final KeyDerive keyDerive; private final byte[] ukm;

    // конструктор
	public RFC4357(Cipher cipher, Mac macAlgorithm, byte[] ukm)
    {
        // сохранить переданные параметры
		this.cipher       = RefObject.addRef(cipher      ); 
		this.macAlgorithm = RefObject.addRef(macAlgorithm); 
        
        // сохранить переданные параметры
        this.keyDerive = new NOKDF(GOST28147.ENDIAN); this.ukm = ukm;
    }
    // конструктор
	public RFC4357(Cipher cipher, Mac macAlgorithm, KeyDerive keyDerive, byte[] ukm)
    {
        // сохранить переданные параметры
		this.cipher       = RefObject.addRef(cipher      ); 
		this.macAlgorithm = RefObject.addRef(macAlgorithm); 
        
        // сохранить переданные параметры
        this.keyDerive = RefObject.addRef(keyDerive); this.ukm = ukm;
    }
    // освободить ресурсы
    @Override protected void onClose() throws IOException   
    { 
        // освободить ресурсы
        RefObject.release(keyDerive); RefObject.release(macAlgorithm);
        
        // освободить ресурсы
        RefObject.release(cipher); super.onClose();
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return cipher.keyFactory(); } 
	// размер ключей
	@Override public final int[] keySizes() { return cipher.keySizes(); }
    
    // зашифровать ключ
	@Override public byte[] wrap(IRand rand, ISecretKey key, ISecretKey wrappedKey) 
        throws IOException, InvalidKeyException
	{
		// проверить тип ключа
		byte[] CEK = wrappedKey.value(); if (CEK == null) throw new InvalidKeyException();
			
        // диверсифицировать ключ
        try (ISecretKey newKey = keyDerive.deriveKey(key, ukm, cipher.keyFactory(), 32))
        {
            // зашифровать ключ
            byte[] encrypted = cipher.encrypt(newKey, PaddingMode.NONE, CEK, 0, CEK.length);

            // вычислить имитовставку
            byte[] imito = macAlgorithm.macData(newKey, CEK, 0, CEK.length); 

            // вернуть зашифрованный ключ и имитовставку
            return Array.concat(encrypted, imito);
        }
 	}
	@Override public ISecretKey unwrap(ISecretKey key, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
	{
        // определить размер зашифрованных данных
        int sizeCEK = wrappedCEK.length - 4;
        
		// проверить размер зашифрованного ключа
		if (sizeCEK != 32 && sizeCEK != 64) throw new IOException();
 
        // диверсифицировать ключ
        try (ISecretKey newKey = keyDerive.deriveKey(key, ukm, cipher.keyFactory(), 32))
        {
            // расшифровать ключ
            byte[] CEK = cipher.decrypt(newKey, PaddingMode.NONE, wrappedCEK, 0, sizeCEK); 
                    
            // вычислить имитовставку
            byte[] imito = macAlgorithm.macData(newKey, CEK, 0, CEK.length);
            
            // проверить совпадение имитовставки
            if (!Array.equals(imito, 0, wrappedCEK, sizeCEK, 4)) throw new IOException();
            
            // вернуть расшифрованный ключ
            return keyFactory.create(CEK); 
        }
	}
}
