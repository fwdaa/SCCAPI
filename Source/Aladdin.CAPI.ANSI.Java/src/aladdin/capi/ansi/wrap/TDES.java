package aladdin.capi.ansi.wrap;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа TDES
///////////////////////////////////////////////////////////////////////////
public class TDES extends KeyWrap
{
    // блочный алгоритм шифрования
    private final IBlockCipher blockCipher; 
    // размер ключа и алгоритм хэширования
    private final int keyLength; private final Hash sha1;
    
	// вектор инициализации
	private static final byte[] IV = new byte[] { 
        (byte)0x4A, (byte)0xDD, (byte)0xA2, (byte)0x2C, 
        (byte)0x79, (byte)0xE8, (byte)0x21, (byte)0x05 
    };
    // конструктор
    public TDES(IBlockCipher blockCipher, int keyLength, Hash sha1) 
    { 
        // сохранить переданные параметры
        this.blockCipher = RefObject.addRef(blockCipher);
        this.sha1        = RefObject.addRef(sha1       ); this.keyLength = keyLength; 
    }
    // освободить ресурсы 
    @Override protected void onClose() throws IOException 
    {
        // освободить ресурсы 
        RefObject.release(sha1); RefObject.release(blockCipher); super.onClose();
    }
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() 
    { 
        // проверить изменение размера 
        if (keyLength == 0) return blockCipher.keyFactory(); 
        
        // указать используемый размер
        return blockCipher.keyFactory().narrow(new int[] {keyLength}); 
    } 
	// зашифровать ключ
	@Override public byte[] wrap(IRand rand, ISecretKey key, ISecretKey wrappedKey) 
        throws IOException, InvalidKeyException
	{
		// проверить тип ключа
		byte[] CEK = wrappedKey.value(); if (CEK == null) throw new InvalidKeyException();
        
		// проверить размер ключа
		if (CEK.length != 24) throw new InvalidKeyException();

		// вычислить контрольную сумму
		byte[] ICV = sha1.hashData(CEK, 0, 24); 

		// объединить ключ и контрольную сумму
        byte[] CEKICV = Array.concat(CEK, Arrays.copyOf(ICV, 8)); 
        
		// сгенерировать случайный вектор инициализации
		byte[] startIV = new byte[8]; rand.generate(startIV, 0, 8);
        
        // создать алгоритм шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CBC(startIV)))
        {
            // зашифровать ключ с контрольной суммой
            CEKICV = cipher.encrypt(key, PaddingMode.NONE, CEKICV, 0, CEKICV.length); 
        }
		// объединить вектор инициализации с зашифрованным ключом
		byte[] IVCEKICV = Array.concat(startIV, CEKICV); Array.reverse(IVCEKICV);

        // создать алгоритм шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CBC(IV)))
        {
            // зашифровать с измененным порядком байтов
            return cipher.encrypt(key, PaddingMode.NONE, IVCEKICV, 0, IVCEKICV.length); 
        }
    }
	// расшифровать ключ
	@Override public ISecretKey unwrap(ISecretKey key, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
	{
		// проверить размер данных
		if (wrappedCEK.length != 40) throw new IOException();
        
        // выделить память для синхропосылки
        byte[] startIV = new byte[8]; byte[] IVCEKICV; byte[] CEKICV; 
        
        // создать алгоритм шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CBC(IV)))
        {
            // расшифровать данные
            IVCEKICV = cipher.decrypt(key, PaddingMode.NONE, wrappedCEK, 0, wrappedCEK.length); 
        }
        // извлечь вектор инициализации
        Array.reverse(IVCEKICV); System.arraycopy(IVCEKICV, 0, startIV, 0, 8); 

        // создать алгоритм шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CBC(startIV)))
        {
            // расшифровать данные
            CEKICV = cipher.decrypt(key, PaddingMode.NONE, IVCEKICV, 8, 32); 
        }
		// вычислить контрольную сумму
		byte[] ICV = sha1.hashData(CEKICV, 0, 24);
        
		// проверить совпадение контрольных сумм
		if (!Array.equals(ICV, 0, CEKICV, 24, 8)) throw new IOException(); 

		// вернуть вычисленный ключ
        return keyFactory.create(Arrays.copyOf(CEKICV, 24));
	}
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(KeyWrap keyWrap) throws Exception
    {
        byte[] random = new byte[] {
            (byte)0x5d, (byte)0xd4, (byte)0xcb, (byte)0xfc, 
            (byte)0x96, (byte)0xf5, (byte)0x45, (byte)0x3b
        }; 
        // создать генератор случайных данных
        try (IRand rand = new aladdin.capi.rnd.Fixed(random)) 
        {
            // выполнить тест
            knownTest(rand, keyWrap, new byte[] {
                (byte)0x25, (byte)0x5e, (byte)0x0d, (byte)0x1c, 
                (byte)0x07, (byte)0xb6, (byte)0x46, (byte)0xdf, 
                (byte)0xb3, (byte)0x13, (byte)0x4c, (byte)0xc8,
                (byte)0x43, (byte)0xba, (byte)0x8a, (byte)0xa7, 
                (byte)0x1f, (byte)0x02, (byte)0x5b, (byte)0x7c, 
                (byte)0x08, (byte)0x38, (byte)0x25, (byte)0x1f        
            }, new byte[] {
                (byte)0x29, (byte)0x23, (byte)0xbf, (byte)0x85, 
                (byte)0xe0, (byte)0x6d, (byte)0xd6, (byte)0xae, 
                (byte)0x52, (byte)0x91, (byte)0x49, (byte)0xf1, 
                (byte)0xf1, (byte)0xba, (byte)0xe9, (byte)0xea, 
                (byte)0xb3, (byte)0xa7, (byte)0xda, (byte)0x3d, 
                (byte)0x86, (byte)0x0d, (byte)0x3e, (byte)0x98        
            }, new byte[] {
                (byte)0x69, (byte)0x01, (byte)0x07, (byte)0x61, 
                (byte)0x8e, (byte)0xf0, (byte)0x92, (byte)0xb3, 
                (byte)0xb4, (byte)0x8c, (byte)0xa1, (byte)0x79, 
                (byte)0x6b, (byte)0x23, (byte)0x4a, (byte)0xe9, 
                (byte)0xfa, (byte)0x33, (byte)0xeb, (byte)0xb4, 
                (byte)0x15, (byte)0x96, (byte)0x04, (byte)0x03, 
                (byte)0x7d, (byte)0xb5, (byte)0xd6, (byte)0xa8, 
                (byte)0x4e, (byte)0xb3, (byte)0xaa, (byte)0xc2, 
                (byte)0x76, (byte)0x8c, (byte)0x63, (byte)0x27, 
                (byte)0x75, (byte)0xa4, (byte)0x67, (byte)0xd4        
            });
        }
    }
}
