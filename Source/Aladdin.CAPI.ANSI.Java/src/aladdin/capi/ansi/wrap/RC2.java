package aladdin.capi.ansi.wrap;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа RC2
///////////////////////////////////////////////////////////////////////////
public class RC2 extends KeyWrap
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
    public RC2(IBlockCipher blockCipher, int keyLength, Hash sha1) 
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
        
		// выделить память для расширения ключа
		byte[] LCEKPAD = new byte[(CEK.length / 8 + 1) * 8]; 
 
		// скопировать ключ и его размер
		LCEKPAD[0] = (byte)CEK.length; System.arraycopy(CEK, 0, LCEKPAD, 1, CEK.length);
			
		// сгенерировать дополнение ключа
		rand.generate(LCEKPAD, 1 + CEK.length, LCEKPAD.length - CEK.length - 1);
 
		// вычислить контрольную сумму
		byte[] ICV = sha1.hashData(LCEKPAD, 0, LCEKPAD.length);
     
		// объединить ключ и контрольную сумму
        byte[] LCEKPADICV = Array.concat(LCEKPAD, Arrays.copyOf(ICV, 8)); 

        // сгенерировать случайный вектор инициализации
        byte[] startIV = new byte[8]; rand.generate(startIV, 0, 8);

        // создать алгоритм шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CBC(startIV)))
        {
            // зашифровать ключ с контрольной суммой
            LCEKPADICV = cipher.encrypt(key, PaddingMode.NONE, LCEKPADICV, 0, LCEKPADICV.length); 
        }
		// объединить вектор инициализации с зашифрованным ключом
		byte[] IVLCEKPADICV = Array.concat(startIV, LCEKPADICV); Array.reverse(IVLCEKPADICV);
        
        // создать алгоритм шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CBC(IV)))
        {
            // зашифровать с измененным порядком байтов
            return cipher.encrypt(key, PaddingMode.NONE, IVLCEKPADICV, 0, IVLCEKPADICV.length); 
        }
    }
	// расшифровать ключ
	@Override public ISecretKey unwrap(ISecretKey key, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
	{
		// проверить размер данных
		if ((wrappedCEK.length % 8) != 0 || wrappedCEK.length < 24) throw new IOException();
        
        // выделить память для синхропосылки
        byte[] startIV = new byte[8]; byte[] IVLCEKPADICV; byte[] LCEKPADICV; 
        
        // создать алгоритм шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CBC(IV)))
        {
            // расшифровать данные
            IVLCEKPADICV = cipher.decrypt(key, PaddingMode.NONE, wrappedCEK, 0, wrappedCEK.length); 
        }
		// изменить порядок байтов и извлечь вектор инициализации
		Array.reverse(IVLCEKPADICV); System.arraycopy(IVLCEKPADICV, 0, startIV, 0, 8);
        
        // создать алгоритм шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CBC(startIV)))
        {
            // расшифровать данные
            LCEKPADICV = cipher.decrypt(key, PaddingMode.NONE, IVLCEKPADICV, 8, IVLCEKPADICV.length - 8); 
        }
		// вычислить контрольную сумму
		byte[] ICV = sha1.hashData(LCEKPADICV, 0, LCEKPADICV.length - 8);
 
		// проверить совпадение контрольных сумм
		if (!Array.equals(ICV, 0, LCEKPADICV, LCEKPADICV.length - 8, 8)) 
		{
			// при ошибке выбросить исключение
			throw new IOException();
		}
		// выделить память для ключа
		byte[] CEK = new byte[LCEKPADICV[0]]; 
			
        // извлечь значение ключа
		System.arraycopy(LCEKPADICV, 1, CEK, 0, CEK.length); 
        
		// вернуть вычисленный ключ
        return keyFactory.create(CEK); 
	}
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test40(KeyWrap keyWrap) throws Exception
    {
        byte[][] random = new byte[][] { 
           new byte[] {
            (byte)0x48, (byte)0x45, (byte)0xcc, (byte)0xe7, 
            (byte)0xfd, (byte)0x12, (byte)0x50
        }, new byte[] {
            (byte)0xc7, (byte)0xd9, (byte)0x00, (byte)0x59, 
            (byte)0xb2, (byte)0x9e, (byte)0x97, (byte)0xf7
        }}; 
        // создать генератор случайных данных
        try (Test.Rand rand = new Test.Rand(random)) 
        {
            // выполнить тест
            knownTest(rand, keyWrap, new byte[] {
                (byte)0xfd, (byte)0x04, (byte)0xfd, (byte)0x08, 
                (byte)0x06, (byte)0x07, (byte)0x07, (byte)0xfb, 
                (byte)0x00, (byte)0x03, (byte)0xfe, (byte)0xff, 
                (byte)0xfd, (byte)0x02, (byte)0xfe, (byte)0x05        
            }, new byte[] {
                (byte)0xb7, (byte)0x0a, (byte)0x25, (byte)0xfb, 
                (byte)0xc9, (byte)0xd8, (byte)0x6a, (byte)0x86, 
                (byte)0x05, (byte)0x0c, (byte)0xe0, (byte)0xd7, 
                (byte)0x11, (byte)0xea, (byte)0xd4, (byte)0xd9
            }, new byte[] {
                (byte)0x70, (byte)0xe6, (byte)0x99, (byte)0xfb, 
                (byte)0x57, (byte)0x01, (byte)0xf7, (byte)0x83, 
                (byte)0x33, (byte)0x30, (byte)0xfb, (byte)0x71, 
                (byte)0xe8, (byte)0x7c, (byte)0x85, (byte)0xa4, 
                (byte)0x20, (byte)0xbd, (byte)0xc9, (byte)0x9a, 
                (byte)0xf0, (byte)0x5d, (byte)0x22, (byte)0xaf, 
                (byte)0x5a, (byte)0x0e, (byte)0x48, (byte)0xd3, 
                (byte)0x5f, (byte)0x31, (byte)0x38, (byte)0x98,
                (byte)0x6c, (byte)0xba, (byte)0xaf, (byte)0xb4, 
                (byte)0xb2, (byte)0x8d, (byte)0x4f, (byte)0x35            
            }); 
        }
    }
    public static void test128(KeyWrap keyWrap) throws Exception
    {
        byte[][] random = new byte[][] { 
           new byte[] {
            (byte)0x48, (byte)0x45, (byte)0xcc, (byte)0xe7, 
            (byte)0xfd, (byte)0x12, (byte)0x50
        }, new byte[] {
            (byte)0xc7, (byte)0xd9, (byte)0x00, (byte)0x59, 
            (byte)0xb2, (byte)0x9e, (byte)0x97, (byte)0xf7
        }}; 
        // создать генератор случайных данных
        try (Test.Rand rand = new Test.Rand(random)) 
        {
            // выполнить тест
            knownTest(rand, keyWrap, new byte[] {
                (byte)0xfd, (byte)0x04, (byte)0xfd, (byte)0x08, 
                (byte)0x06, (byte)0x07, (byte)0x07, (byte)0xfb, 
                (byte)0x00, (byte)0x03, (byte)0xfe, (byte)0xff, 
                (byte)0xfd, (byte)0x02, (byte)0xfe, (byte)0x05        
            }, new byte[] {
                (byte)0xb7, (byte)0x0a, (byte)0x25, (byte)0xfb, 
                (byte)0xc9, (byte)0xd8, (byte)0x6a, (byte)0x86, 
                (byte)0x05, (byte)0x0c, (byte)0xe0, (byte)0xd7, 
                (byte)0x11, (byte)0xea, (byte)0xd4, (byte)0xd9
            }, new byte[] {
                (byte)0xf4, (byte)0xd8, (byte)0x02, (byte)0x1c, 
                (byte)0x1e, (byte)0xa4, (byte)0x63, (byte)0xd2, 
                (byte)0x17, (byte)0xa9, (byte)0xeb, (byte)0x69, 
                (byte)0x29, (byte)0xff, (byte)0xa5, (byte)0x77, 
                (byte)0x36, (byte)0xd3, (byte)0xe2, (byte)0x03,
                (byte)0x86, (byte)0xc9, (byte)0x09, (byte)0x93, 
                (byte)0x83, (byte)0x5b, (byte)0x4b, (byte)0xe4, 
                (byte)0xad, (byte)0x8d, (byte)0x8a, (byte)0x1b, 
                (byte)0xc6, (byte)0x3b, (byte)0x25, (byte)0xde, 
                (byte)0x2b, (byte)0xf7, (byte)0x79, (byte)0x93        
            }); 
        }
    }
}
