package aladdin.capi.ansi.wrap;
import aladdin.*; 
import aladdin.math.*;
import aladdin.capi.*;
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа AES
///////////////////////////////////////////////////////////////////////////
public class AES extends KeyWrap
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
	// вектор инициализации по умолчанию
	private static final byte[] DEFAULT_IV = new byte[] {
        (byte)0xA6, (byte)0xA6, (byte)0xA6, (byte)0xA6, 
        (byte)0xA6, (byte)0xA6, (byte)0xA6, (byte)0xA6 
    }; 
	// алгоритм шифрования и синхропосылка
	private final Cipher aesECB; private final byte[] iv;    
    
    // конструктор 
	public AES(Cipher aesECB, byte[] iv) 
    {
        // сохранить переданные параметры
        this.aesECB = RefObject.addRef(aesECB); this.iv = iv;
    } 
    // конструктор 
	public AES(Cipher aesECB) { this(aesECB, DEFAULT_IV); }
    
    // освободить ресурсы 
    @Override protected void onClose() throws IOException 
    {
        // освободить ресурсы 
        RefObject.release(aesECB); super.onClose();            
    }
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() { return aesECB.keyFactory(); } 

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
		// проверить размер ключа
		if ((CEK.length % 8) != 0) throw new InvalidKeyException();
        
        // получить преобразование зашифрования
        try (Transform encryption = aesECB.createEncryption(KEK, PaddingMode.NONE)) 
        {
            // установить начальные значения
            byte[] A = iv.clone(); byte[] R = CEK.clone(); 

            // выделить память для переменных
            byte[] block = new byte[16]; byte[] number = new byte[8];  

            // выполнить 6 раз
            encryption.init(); for (int j = 0; j < 6; j++)
            {
                // для всех блоков зашифровываемого ключа
                for (int i = 0; i < R.length / 8; i++)
                {
                    // определить номер шага
                    int index = (R.length / 8 * j + i + 1); 

                    // закодировать номер шага
                    Convert.fromInt64(index, ENDIAN, number, 0);

                    // создать блок для зашифрования
                    System.arraycopy(A,     0, block, 0, 8);
                    System.arraycopy(R, 8 * i, block, 8, 8); 

                    // зашифровать блок
                    encryption.update(block, 0, block.length, block, 0); 

                    // разбить блок на части
                    System.arraycopy(block, 0, A,     0, 8);
                    System.arraycopy(block, 8, R, 8 * i, 8); 

                    // добавить номер шага
                    for (int k = 0; k < 8; k++) A[k] ^= number[k]; 
                }
            }
            // вернуть зашифрованный ключ
            return Array.concat(A, R); 
        }
	}
	// расшифровать ключ
	@Override public ISecretKey unwrap(ISecretKey KEK, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
	{
		// проверить размер ключа
		if ((wrappedCEK.length % 8) != 0 || wrappedCEK.length < 16) 
		{
			// при ошибке выбросить исключение
			throw new IOException();
		}
        // получить преобразование расшифрования
        try (Transform decryption = aesECB.createDecryption(KEK, PaddingMode.NONE)) 
        {
            // выделить память для переменных 
            byte[] A = new byte[8]; byte[] R = new byte[wrappedCEK.length - 8]; 

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
            // проверить совпадение вектора инициализации
            if (!Array.equals(A, 0, iv, 0, iv.length)) throw new IOException(); 

            // вернуть расшифрованный ключ
            return keyFactory.create(R); 
        }
	}
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(KeyWrap keyWrap) throws Exception
    {
        int[] keySizes = keyWrap.keyFactory().keySizes(); 
        
        if (KeySizes.contains(keySizes, 16))
        knownTest(null, keyWrap, new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, 
            (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F
        }, new byte[] {
            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
            (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
            (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
            (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF
        }, new byte[] {
            (byte)0x1F, (byte)0xA6, (byte)0x8B, (byte)0x0A, 
            (byte)0x81, (byte)0x12, (byte)0xB4, (byte)0x47, 
            (byte)0xAE, (byte)0xF3, (byte)0x4B, (byte)0xD8, 
            (byte)0xFB, (byte)0x5A, (byte)0x7B, (byte)0x82, 
            (byte)0x9D, (byte)0x3E, (byte)0x86, (byte)0x23, 
            (byte)0x71, (byte)0xD2, (byte)0xCF, (byte)0xE5
        }); 
        if (KeySizes.contains(keySizes, 24))
        knownTest(null, keyWrap, new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, 
            (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F, 
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17
        }, new byte[] {
            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
            (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
            (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
            (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF
        }, new byte[] {
            (byte)0x96, (byte)0x77, (byte)0x8B, (byte)0x25, 
            (byte)0xAE, (byte)0x6C, (byte)0xA4, (byte)0x35, 
            (byte)0xF9, (byte)0x2B, (byte)0x5B, (byte)0x97, 
            (byte)0xC0, (byte)0x50, (byte)0xAE, (byte)0xD2, 
            (byte)0x46, (byte)0x8A, (byte)0xB8, (byte)0xA1, 
            (byte)0x7A, (byte)0xD8, (byte)0x4E, (byte)0x5D
        }); 
        if (KeySizes.contains(keySizes, 32))
        knownTest(null, keyWrap, new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, 
            (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F, 
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
            (byte)0x18, (byte)0x19, (byte)0x1A, (byte)0x1B, 
            (byte)0x1C, (byte)0x1D, (byte)0x1E, (byte)0x1F
        }, new byte[] {
            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
            (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
            (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
            (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF
        }, new byte[] {
            (byte)0x64, (byte)0xE8, (byte)0xC3, (byte)0xF9, 
            (byte)0xCE, (byte)0x0F, (byte)0x5B, (byte)0xA2, 
            (byte)0x63, (byte)0xE9, (byte)0x77, (byte)0x79, 
            (byte)0x05, (byte)0x81, (byte)0x8A, (byte)0x2A, 
            (byte)0x93, (byte)0xC8, (byte)0x19, (byte)0x1E, 
            (byte)0x7D, (byte)0x6E, (byte)0x8A, (byte)0xE7
        }); 
        if (KeySizes.contains(keySizes, 24))
        knownTest(null, keyWrap, new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, 
            (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F, 
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17
        }, new byte[] {
            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
            (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
            (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
            (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, 
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07
        }, new byte[] {
            (byte)0x03, (byte)0x1D, (byte)0x33, (byte)0x26, 
            (byte)0x4E, (byte)0x15, (byte)0xD3, (byte)0x32, 
            (byte)0x68, (byte)0xF2, (byte)0x4E, (byte)0xC2, 
            (byte)0x60, (byte)0x74, (byte)0x3E, (byte)0xDC, 
            (byte)0xE1, (byte)0xC6, (byte)0xC7, (byte)0xDD, 
            (byte)0xEE, (byte)0x72, (byte)0x5A, (byte)0x93, 
            (byte)0x6B, (byte)0xA8, (byte)0x14, (byte)0x91, 
            (byte)0x5C, (byte)0x67, (byte)0x62, (byte)0xD2
        }); 
        if (KeySizes.contains(keySizes, 32))
        knownTest(null, keyWrap, new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, 
            (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F, 
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
            (byte)0x18, (byte)0x19, (byte)0x1A, (byte)0x1B, 
            (byte)0x1C, (byte)0x1D, (byte)0x1E, (byte)0x1F
        }, new byte[] {
            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
            (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
            (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
            (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, 
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07
        }, new byte[] {
            (byte)0xA8, (byte)0xF9, (byte)0xBC, (byte)0x16, 
            (byte)0x12, (byte)0xC6, (byte)0x8B, (byte)0x3F, 
            (byte)0xF6, (byte)0xE6, (byte)0xF4, (byte)0xFB, 
            (byte)0xE3, (byte)0x0E, (byte)0x71, (byte)0xE4, 
            (byte)0x76, (byte)0x9C, (byte)0x8B, (byte)0x80, 
            (byte)0xA3, (byte)0x2C, (byte)0xB8, (byte)0x95, 
            (byte)0x8C, (byte)0xD5, (byte)0xD1, (byte)0x7D, 
            (byte)0x6B, (byte)0x25, (byte)0x4D, (byte)0xA1
        }); 
        if (KeySizes.contains(keySizes, 32))
        knownTest(null, keyWrap, new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, 
            (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F, 
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
            (byte)0x18, (byte)0x19, (byte)0x1A, (byte)0x1B, 
            (byte)0x1C, (byte)0x1D, (byte)0x1E, (byte)0x1F
        }, new byte[] {
            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
            (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
            (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
            (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, 
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, 
            (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F
        }, new byte[] {
            (byte)0x28, (byte)0xC9, (byte)0xF4, (byte)0x04, 
            (byte)0xC4, (byte)0xB8, (byte)0x10, (byte)0xF4, 
            (byte)0xCB, (byte)0xCC, (byte)0xB3, (byte)0x5C, 
            (byte)0xFB, (byte)0x87, (byte)0xF8, (byte)0x26,
            (byte)0x3F, (byte)0x57, (byte)0x86, (byte)0xE2, 
            (byte)0xD8, (byte)0x0E, (byte)0xD3, (byte)0x26, 
            (byte)0xCB, (byte)0xC7, (byte)0xF0, (byte)0xE7, 
            (byte)0x1A, (byte)0x99, (byte)0xF4, (byte)0x3B, 
            (byte)0xFB, (byte)0x98, (byte)0x8B, (byte)0x9B, 
            (byte)0x7A, (byte)0x02, (byte)0xDD, (byte)0x21
        });  
    }
}
