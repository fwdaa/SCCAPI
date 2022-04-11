package aladdin.capi.gost.engine;
import aladdin.math.*; 
import aladdin.capi.*; 
import java.security.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования GOST28147-89
///////////////////////////////////////////////////////////////////////////
public class GOST28147 extends Cipher
{
    // способ кодирования чисел
    public static final Endian ENDIAN = Endian.LITTLE_ENDIAN;
    
    // таблица подстановок и способ кодирования чисел
    private final byte[] sbox; private final Endian endian; 
        
    // конструктор
    public GOST28147(byte[] sbox) { this(sbox, ENDIAN); }
            
    // конструктор
    protected GOST28147(byte[] sbox, Endian endian) 
    { 
        // сохранить переданные параметры
        this.sbox = sbox; this.endian = endian; 
    } 
    // тип ключа
    @Override public SecretKeyFactory keyFactory() 
    { 
        // вернуть тип ключа
        return aladdin.capi.gost.keys.GOST.INSTANCE; 
    } 
    // размер блока
	@Override public final int blockSize() { return 8;	}

    // используемая таблица подстановок
    public final byte[] sbox() { return sbox; }

	// алгоритм зашифрования блока данных
	@Override protected final Transform createEncryption(ISecretKey key) 
        throws InvalidKeyException
	{
		// проверить тип ключа
		byte[] value = key.value(); if (value == null)
		{
			// при ошибке выбросить исключение
			throw new InvalidKeyException();
		}
        // проверить размер ключа
        if (value.length != 32) throw new InvalidKeyException(); 
            
		// вернуть алгоритм зашифрования блока данных
		return new Encryption(sbox, key, endian); 
	}
	// алгоритм расшифрования блока данных
	@Override protected final Transform createDecryption(ISecretKey key) 
        throws InvalidKeyException
	{
		// проверить тип ключа
		byte[] value = key.value(); if (value == null)
		{
			// при ошибке выбросить исключение
			throw new InvalidKeyException();
		}
        // проверить размер ключа
        if (value.length != 32) throw new InvalidKeyException(); 
            
		// вернуть алгоритм расшифрования блока данных
		return new Decryption(sbox, key, endian);
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Encryption extends BlockTransform
	{
		// используемая таблица подстановок и способ кодирования чисел
		private final byte[] sbox; private final Endian endian; 
        
        // расписание ключей
        private final int[] keys = new int[32];

		// Конструктор
		public Encryption(byte[] sbox, ISecretKey key, Endian endian) throws InvalidKeyException
		{ 
			// проверить тип ключа
			super(8); this.sbox = sbox; byte[] value = key.value(); 
            
            // проверить корректность параметров
            if (value == null) throw new InvalidKeyException(); this.endian = endian; 
            
			// установить ключ
			for (int i = 0; i < 8; i++) 
			{
				keys[i +  0] = Convert.toInt32(value,      i  * 4, endian); 
				keys[i +  8] = Convert.toInt32(value,      i  * 4, endian); 
				keys[i + 16] = Convert.toInt32(value,      i  * 4, endian); 
				keys[i + 24] = Convert.toInt32(value, (7 - i) * 4, endian);
			}
		}
		@Override protected void update(
            byte[] src, int srcOff, byte[] dest, int destOff)
		{
            // указать смещения
            int offsetN1 = (endian == Endian.LITTLE_ENDIAN) ? 0 : 4; 
            int offsetN2 = (endian == Endian.LITTLE_ENDIAN) ? 4 : 0; 

			// извлечь обрабатываемый блок
			int N1 = Convert.toInt32(src, srcOff + offsetN1, endian); 
			int N2 = Convert.toInt32(src, srcOff + offsetN2, endian); 

			// выполнить первые 31 шагов
			for(int j = 0; j < 31; j++)
			{
				// выполнить очередной шаг
				int N = N1; N1 = N2 ^ step(sbox, N1, keys[j]); N2 = N;
			}
			// выполнить последний шаг
			N2 = N2 ^ step(sbox, N1, keys[31]);

			// вернуть обработанный блок
            Convert.fromInt32(N1, endian, dest, destOff + offsetN1); 
            Convert.fromInt32(N2, endian, dest, destOff + offsetN2); 
        }
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм расшифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Decryption extends BlockTransform
	{
		// используемая таблица подстановок и способ кодирования чисел
		private final byte[] sbox; private final Endian endian; 
        
        // расписание ключей
        private final int[] keys = new int[32];

		// Конструктор
		public Decryption(byte[] sbox, ISecretKey key, Endian endian) throws InvalidKeyException 
		{ 
			// проверить тип ключа
			super(8); this.sbox = sbox; byte[] value = key.value(); 
            
            // проверить корректность параметров
            if (value == null) throw new InvalidKeyException(); this.endian = endian; 
            
			// установить ключ
			for (int i = 0; i < 8; i++) 
			{
				keys[i +  0] = Convert.toInt32(value,      i  * 4, endian); 
				keys[i +  8] = Convert.toInt32(value, (7 - i) * 4, endian);
				keys[i + 16] = Convert.toInt32(value, (7 - i) * 4, endian);
				keys[i + 24] = Convert.toInt32(value, (7 - i) * 4, endian);
			}
		}
		@Override protected void update(
            byte[] src, int srcOff, byte[] dest, int destOff)
		{
            // указать смещения
            int offsetN1 = (endian == Endian.LITTLE_ENDIAN) ? 0 : 4; 
            int offsetN2 = (endian == Endian.LITTLE_ENDIAN) ? 4 : 0; 

			// извлечь обрабатываемый блок
			int N1 = Convert.toInt32(src, srcOff + offsetN1, endian); 
			int N2 = Convert.toInt32(src, srcOff + offsetN2, endian); 

			// выполнить первые 31 шагов
			for(int j = 0; j < 31; j++)
			{
				// выполнить очередной шаг
				int N = N1; N1 = N2 ^ step(sbox, N1, keys[j]); N2 = N;
			}
			// выполнить последний шаг
			N2 = N2 ^ step(sbox, N1, keys[31]);

			// вернуть обработанный блок
            Convert.fromInt32(N1, endian, dest, destOff + offsetN1); 
            Convert.fromInt32(N2, endian, dest, destOff + offsetN2); 
		}
	}
	///////////////////////////////////////////////////////////////////////////
	// Тактовая функция
	///////////////////////////////////////////////////////////////////////////
	private static int step(byte[] sbox, int n1, int key)
	{
		// добавить ключ к блоку
		int cm = key + n1; int om = 0;

		// выполнить подстановку
		om = om + ((sbox[      ((cm       ) & 0xF)] & 0xFF)      );
		om = om + ((sbox[ 16 + ((cm >>>  4) & 0xF)] & 0xFF) <<  4);
		om = om + ((sbox[ 32 + ((cm >>>  8) & 0xF)] & 0xFF) <<  8);
		om = om + ((sbox[ 48 + ((cm >>> 12) & 0xF)] & 0xFF) << 12);
		om = om + ((sbox[ 64 + ((cm >>> 16) & 0xF)] & 0xFF) << 16);
		om = om + ((sbox[ 80 + ((cm >>> 20) & 0xF)] & 0xFF) << 20);
		om = om + ((sbox[ 96 + ((cm >>> 24) & 0xF)] & 0xFF) << 24);
		om = om + ((sbox[112 + ((cm >>> 28) & 0xF)] & 0xFF) << 28);

		// выполнить циклический сдвиг
		return om << 11 | om >>> (32 - 11);
	}
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void testZ(Cipher engine) throws Exception
    {
        // указать ключ
        byte[] key = new byte[] {
            (byte)0x81, (byte)0x82, (byte)0x83, (byte)0x84, 
            (byte)0x85, (byte)0x86, (byte)0x87, (byte)0x88, 
            (byte)0x89, (byte)0x8a, (byte)0x8b, (byte)0x8c, 
            (byte)0x8d, (byte)0x8e, (byte)0x8f, (byte)0x80, 
            (byte)0xd1, (byte)0xd2, (byte)0xd3, (byte)0xd4, 
            (byte)0xd5, (byte)0xd6, (byte)0xd7, (byte)0xd8, 
            (byte)0xd9, (byte)0xda, (byte)0xdb, (byte)0xdc, 
            (byte)0xdd, (byte)0xde, (byte)0xdf, (byte)0xd0 
        };
        // выполнить тест
        Cipher.knownTest(engine, PaddingMode.NONE, key, new byte[] {
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08 
        }, new byte[] {
            (byte)0xce, (byte)0x5a, (byte)0x5e, (byte)0xd7, 
            (byte)0xe0, (byte)0x57, (byte)0x7a, (byte)0x5f 
        });
        // выполнить тест
        Cipher.knownTest(engine, PaddingMode.NONE, key, new byte[] {
            (byte)0xf1, (byte)0xf2, (byte)0xf3, (byte)0xf4, 
            (byte)0xf5, (byte)0xf6, (byte)0xf7, (byte)0xf8
        }, new byte[] {
            (byte)0xd0, (byte)0xcc, (byte)0x85, (byte)0xce, 
            (byte)0x31, (byte)0x63, (byte)0x5b, (byte)0x8b
        }); 
    }
}
