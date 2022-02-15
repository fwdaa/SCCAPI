package aladdin.capi.ansi.wrap;
import aladdin.*; 
import aladdin.math.*;
import aladdin.capi.*;
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа AES с дополнением
///////////////////////////////////////////////////////////////////////////
public class AES_PAD extends KeyWrap
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
	// вектор инициализации по умолчанию
	private static final byte[] DEFAULT_IV = new byte[] { 
        (byte)0xA6, (byte)0x59, (byte)0x59, (byte)0xA6 
    }; 
    // алгоритм шифрования и синхропосылка
    private final Cipher aesECB; private final byte[] iv;   
    
    // конструктор 
    public AES_PAD(Cipher aesECB, byte[] iv) 
    {
        // сохранить переданные параметры
        this.aesECB = RefObject.addRef(aesECB); this.iv = iv;
    }
    // конструктор 
    public AES_PAD(Cipher aesECB) { this(aesECB, DEFAULT_IV); }
        
    // освободить ресурсы 
    @Override protected void onClose() throws IOException  
    {
        // освободить ресурсы 
        RefObject.release(aesECB); super.onClose();            
    }
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() { return aesECB.keyFactory(); } 
    // размер ключей
    @Override public final int[] keySizes() { return aesECB.keySizes(); } 

    // зашифровать ключ
	@Override public byte[] wrap(IRand rand, ISecretKey KEK, ISecretKey wrappedKey) 
        throws IOException, InvalidKeyException
	{
		// проверить тип ключа
		byte[] CEK = wrappedKey.value(); if (CEK == null)
		{
			// при ошибке выбросить исключение
			throw new InvalidKeyException();
		}
		// определить размер дополненных данных
		int cbPadded = (CEK.length + 7) / 8 * 8;  

		// дополнить данные 
		byte[] R = new byte[cbPadded]; System.arraycopy(CEK, 0, R, 0, CEK.length);
  
		// сформировать вектор инициализации
		byte[] A = new byte[8]; System.arraycopy(iv, 0, A, 0, 4);
 
		// закодировать размер
        Convert.fromInt32(CEK.length, ENDIAN, A, 4);
            
        // сформировать блок для зашифрования
        if (R.length == 8) { byte[] block = Array.concat(A, R);  

            // получить преобразование зашифрования
            try (Transform encryption = aesECB.createEncryption(KEK, PaddingMode.NONE)) 
            {
                // зашифровать блок
                return encryption.transformData(block, 0, block.length); 
            }
        }
        else {
            // создать алгоритм шифрования дополненного ключа
            try (KeyWrap keyWrap = new AES(aesECB, A))
            {
                // указать используемый ключ
                try (ISecretKey k = SecretKeyFactory.GENERIC.create(R))
                {
                    // зашифровать ключ 
                    return keyWrap.wrap(rand, KEK, k); 
                }
            }
        }
    }
	// расшифровать ключ
	@Override public ISecretKey unwrap(ISecretKey KEK, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
	{
		// проверить размер ключа
		if (wrappedCEK.length < 16 || (wrappedCEK.length % 8) != 0) 
		{
			// при ошибке выбросить исключение
			throw new IOException();
		}
        // получить преобразование расшифрования
        try (Transform decryption = aesECB.createDecryption(KEK, PaddingMode.NONE))
        {
            // обработать частный случай
            byte[] A; byte[] R; if (wrappedCEK.length == 16) 
            {
                // расшифровать блок
                byte[] block = decryption.transformData(wrappedCEK, 0, wrappedCEK.length);
                
                // разбить блок на части
                A = new byte[8]; System.arraycopy(block, 0, A, 0, 8);
                R = new byte[8]; System.arraycopy(block, 8, R, 0, 8); 
            }
            else {
                // выделить память для переменных 
                A = new byte[8]; R = new byte[wrappedCEK.length - 8]; 

                // установить начальные условия
                System.arraycopy(wrappedCEK, 0, A, 0,                     8); 
                System.arraycopy(wrappedCEK, 8, R, 0, wrappedCEK.length - 8); 

                // выделить память для переменных
                byte[] block = new byte[16]; byte[] number = new byte[8];  

                // выполнить 6 раз
                decryption.init(); for (int j = 5; j >= 0; j--)
                {
                    // для всех блоков зашифровываемого ключа
                    for (int i = R.length / 8 - 1; i >= 0; i--)
                    {
                        // определить номер шага
                        int index = (R.length / 8 * j + i + 1); 

                        // закодировать номер шага
                        Convert.fromInt64(index, ENDIAN, number, 0);

                        // добавить номер шага
                        for (int k = 0; k < 8; k++) A[k] ^= number[k]; 

                        // создать блок для зашифрования
                        System.arraycopy(A,     0, block, 0, 8);
                        System.arraycopy(R, 8 * i, block, 8, 8); 

                        // расшифровать блок
                        decryption.update(block, 0, block.length, block, 0);

                        // разбить блок на части
                        System.arraycopy(block, 0, A,     0, 8);
                        System.arraycopy(block, 8, R, 8 * i, 8); 
                    }
                }
            } 
            // проверить совпадение вектора инициализации
            if (!Array.equals(A, 0, iv, 0, 4)) throw new IOException();

            // определить число байтов ключа
            int cbCEK = Convert.toInt32(A, 4, ENDIAN); 

            // проверить корректность размера
            if (R.length < cbCEK || cbCEK <= R.length - 8) throw new IOException();

            // извлечь зашифрованный ключ
            return keyFactory.create(Arrays.copyOf(R, cbCEK)); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(KeyWrap keyWrap) throws Exception
    {
        if (KeySizes.contains(keyWrap.keySizes(), 24))
        knownTest(null, keyWrap, new byte[] {
            (byte)0x58, (byte)0x40, (byte)0xdf, (byte)0x6e, 
            (byte)0x29, (byte)0xb0, (byte)0x2a, (byte)0xf1, 
            (byte)0xab, (byte)0x49, (byte)0x3b, (byte)0x70, 
            (byte)0x5b, (byte)0xf1, (byte)0x6e, (byte)0xa1, 
            (byte)0xae, (byte)0x83, (byte)0x38, (byte)0xf4, 
            (byte)0xdc, (byte)0xc1, (byte)0x76, (byte)0xa8
        }, new byte[] {
            (byte)0xc3, (byte)0x7b, (byte)0x7e, (byte)0x64, 
            (byte)0x92, (byte)0x58, (byte)0x43, (byte)0x40, 
            (byte)0xbe, (byte)0xd1, (byte)0x22, (byte)0x07, 
            (byte)0x80, (byte)0x89, (byte)0x41, (byte)0x15, 
            (byte)0x50, (byte)0x68, (byte)0xf7, (byte)0x38
        }, new byte[] {
            (byte)0x13, (byte)0x8b, (byte)0xde, (byte)0xaa, 
            (byte)0x9b, (byte)0x8f, (byte)0xa7, (byte)0xfc, 
            (byte)0x61, (byte)0xf9, (byte)0x77, (byte)0x42, 
            (byte)0xe7, (byte)0x22, (byte)0x48, (byte)0xee, 
            (byte)0x5a, (byte)0xe6, (byte)0xae, (byte)0x53, 
            (byte)0x60, (byte)0xd1, (byte)0xae, (byte)0x6a,
            (byte)0x5f, (byte)0x54, (byte)0xf3, (byte)0x73, 
            (byte)0xfa, (byte)0x54, (byte)0x3b, (byte)0x6a
        });  
        if (KeySizes.contains(keyWrap.keySizes(), 24))
        knownTest(null, keyWrap, new byte[] {
            (byte)0x58, (byte)0x40, (byte)0xdf, (byte)0x6e, 
            (byte)0x29, (byte)0xb0, (byte)0x2a, (byte)0xf1, 
            (byte)0xab, (byte)0x49, (byte)0x3b, (byte)0x70, 
            (byte)0x5b, (byte)0xf1, (byte)0x6e, (byte)0xa1, 
            (byte)0xae, (byte)0x83, (byte)0x38, (byte)0xf4, 
            (byte)0xdc, (byte)0xc1, (byte)0x76, (byte)0xa8
        }, new byte[] {
            (byte)0x46, (byte)0x6f, (byte)0x72, (byte)0x50, 
            (byte)0x61, (byte)0x73, (byte)0x69
        }, new byte[] {
            (byte)0xaf, (byte)0xbe, (byte)0xb0, (byte)0xf0, 
            (byte)0x7d, (byte)0xfb, (byte)0xf5, (byte)0x41, 
            (byte)0x92, (byte)0x00, (byte)0xf2, (byte)0xcc, 
            (byte)0xb5, (byte)0x0b, (byte)0xb2, (byte)0x4f
        });  
    }
}
