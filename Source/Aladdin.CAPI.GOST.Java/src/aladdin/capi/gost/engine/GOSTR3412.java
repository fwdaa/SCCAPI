package aladdin.capi.gost.engine;
import aladdin.math.*; 
import aladdin.capi.*; 
import aladdin.capi.CipherMode; 
import aladdin.capi.gost.derive.*;
import aladdin.capi.gost.mac.*;
import aladdin.capi.gost.mode.gostr3412.*;
import java.security.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ГОСТ P34.12-2015
///////////////////////////////////////////////////////////////////////////
public final class GOSTR3412 extends Cipher
{
    // способ кодирования чисел
    public static final Endian ENDIAN = Endian.BIG_ENDIAN;
    
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.gost.keys.GOSTR3412.INSTANCE; 
    } 
    // размер блока
	@Override public int blockSize() { return 16; }

	// алгоритм зашифрования блока данных
	@Override protected Transform createEncryption(ISecretKey key) 
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
		return new Encryption(key); 
	}
	// алгоритм расшифрования блока данных
	@Override protected Transform createDecryption(ISecretKey key) 
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
		return new Decryption(key);
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Encryption extends BlockTransform
	{
	    // расписание ключей
	    private final byte[][] keys; 
        
	    // конструктор
        public Encryption(ISecretKey key) throws InvalidKeyException
	    { 
		    // проверить тип ключа
		    super(16); byte[] value = key.value(); if (value == null)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
            // выполнить расширение ключа
            keys = expandKey(key.value()); 
	    }
		@Override protected void update(
            byte[] src, int srcOff, byte[] dest, int destOff)
		{
            // скопировать данные
            byte[] result = new byte[16]; System.arraycopy(src, srcOff, result, 0, 16); 

            // выполнить преобразования
            for (int i = 0; i < 9; i++) LSX(keys[i], result, result); 

            // выполнить сложение
            for (int j = 0; j < 16; j++) result[j] ^= keys[9][j]; 

            // скопировать результат
            System.arraycopy(result, 0, dest, destOff, 16); 
        }
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм расшифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Decryption extends BlockTransform
	{
        // расписание ключей
		private final byte[][] keys; 
        
        // конструктор
        public Decryption(ISecretKey key) throws InvalidKeyException
		{ 
            // проверить тип ключа
			super(16); byte[] value = key.value(); if (value == null)
			{
                // при ошибке выбросить исключение
				throw new InvalidKeyException();
			}
            // выполнить расширение ключа
            keys = expandKey(key.value()); 
		}
		@Override protected void update(
            byte[] src, int srcOff, byte[] dest, int destOff)
		{
            // скопировать данные
            byte[] result = new byte[16]; System.arraycopy(src, srcOff, result, 0, 16); 

            // выполнить преобразования
            for (int i = 9; i > 0; i--) reverseLSX(keys[i], result, result); 

            // выполнить сложение
            for (int j = 0; j < 16; j++) result[j] ^= keys[0][j]; 

            // скопировать результат
            System.arraycopy(result, 0, dest, destOff, 16); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Используемые преобразования 
    ///////////////////////////////////////////////////////////////////////
    private static byte multTable(int index)
    {
        // вернуть значение из соответствующей таблицы
        if (index < 0x2000) return GOSTR3412_1.MULT_TABLE[index % 0x2000]; 
        if (index < 0x4000) return GOSTR3412_2.MULT_TABLE[index % 0x2000]; 
        if (index < 0x6000) return GOSTR3412_3.MULT_TABLE[index % 0x2000]; 
        if (index < 0x8000) return GOSTR3412_4.MULT_TABLE[index % 0x2000]; 
        if (index < 0xA000) return GOSTR3412_5.MULT_TABLE[index % 0x2000]; 
        if (index < 0xC000) return GOSTR3412_6.MULT_TABLE[index % 0x2000]; 
        if (index < 0xE000) return GOSTR3412_7.MULT_TABLE[index % 0x2000]; 

        // вернуть значение из соответствующей таблицы
        return GOSTR3412_8.MULT_TABLE[index % 0x2000]; 
    }
    private static byte linear(byte[] a)
    {
        // коэффициенты умножения в преобразовании l
        byte sum = 0; byte[] kB = { 
            (byte)148, (byte) 32, (byte)133, (byte) 16, (byte)194, (byte)192, (byte)  1, (byte)251, 
            (byte)  1, (byte)192, (byte)194, (byte) 16, (byte)133, (byte) 32, (byte)148, (byte)  1 
        }; 
        // выполнить линейное преобразование
        for (int i = 0; i < 16; ++i) 
        {
            // выполнить линейное преобразование
            sum ^= multTable((a[i] & 0xFF) * 256 + (kB[i] & 0xFF)); 
        }
        return sum; 
    }
    private static void R(byte[] a, byte[] result)
    {
        // выполнить линейное преобразование и сдвиг
        byte sum = linear(a); System.arraycopy(a, 0, result, 1, 15); result[0] = sum; 
    }
    private static void reverseR(byte[] a, byte[] result)
    {
        // выполнить циклический сдвиг
        byte a0 = a[0]; System.arraycopy(a, 1, result, 0, 15); 

        // выполнить линейное преобразование
        result[15] = a0; result[15] = linear(result); 
    }
    private static void L(byte[] a, byte[] result)
    {
        // скопировать данные
        System.arraycopy(a, 0, result, 0, 16); 

        // выполнить преобразования
        for (int i = 0; i < 16; i++) R(result, result); 
    }
    private static void reverseL(byte[] a, byte[] result)
    {
        // скопировать данные
        System.arraycopy(a, 0, result, 0, 16); 

        // выполнить преобразования
        for (int i = 0; i < 16; i++) reverseR(result, result); 
    }
    private static void LSX(byte[] k, byte[] a, byte[] result)
    {
        // для всех байтов
        for (int i = 0; i < 16; i++)
        {
            // выполнить сложение и подстановку
            result[i] = PI[(k[i] & 0xFF) ^ (a[i] & 0xFF)]; 
        }
        // выполнить линейное преобразование
        L(result, result); 
    }
    private static void reverseLSX(byte[] k, byte[] a, byte[] result)
    {
        // выполнить поразрядное сложение
        for (int i = 0; i < 16; i++) result[i] = (byte)(k[i] ^ a[i]);

        // выполнить линейное преобразование
        reverseL(result, result); for (int i = 0; i < 16; i++)
        {
            // выполнить обратную подстановку
            result[i] = REVERSE_PI[result[i] & 0xFF]; 
        }
    }
    private static byte[][] expandKey(byte[] key)
    {
        // выделить память для результата
        byte[][] keys = new byte[10][]; byte[] C = new byte[16]; 
            
        // выделить память для отдельных ключей
        for (int i = 0; i < keys.length; i++) keys[i] = new byte[16]; 

        // инициализировать набор ключей
        System.arraycopy(key,  0, keys[0], 0, 16); 
        System.arraycopy(key, 16, keys[1], 0, 16); 

        // для оставшихся ключей
        for (int i = 0; i < 4; i++)
        {
            // установить начальное значение ключей
            System.arraycopy(keys[2 * i    ], 0, keys[2 * i + 2], 0, 16); 
            System.arraycopy(keys[2 * i + 1], 0, keys[2 * i + 3], 0, 16); 

            // для 8-ми итераций
            for (int j = 1; j <= 8; j++)
            {
                // обнулить старшие байты
                for (int k = 0; k < 15; k++) C[k] = 0; 

                // указать номер итерации
                C[15] = (byte)(i * 8 + j); L(C, C);

                // выполнить преобразование
                LSX(C, keys[2 * i + 2], C); 
            
                // выполнить поразрядное сложение
                for (int k = 0; k < 16; k++) C[k] ^= keys[2 * i + 3][k];

                // установить отдельные ключи
                System.arraycopy(keys[2 * i + 2], 0, keys[2 * i + 3], 0, 16); 
                System.arraycopy(C              , 0, keys[2 * i + 2], 0, 16); 
            }
        }
        return keys; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Таблица подстановок для 64-битного преобразования
    ///////////////////////////////////////////////////////////////////////
    private static final byte[] SBOX_Z = {
        0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1,
        0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf,
        0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0,
        0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb,
        0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc,
        0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0,
        0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7,
        0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2
    }; 
    ///////////////////////////////////////////////////////////////////////
    // Таблица подстановок для 128-битного преобразования
    ///////////////////////////////////////////////////////////////////////
    private static final byte[] PI = {
	    (byte)252, (byte)238, (byte)221, (byte) 17, (byte)207, (byte)110, (byte) 49, (byte) 22, 
        (byte)251, (byte)196, (byte)250, (byte)218, (byte) 35, (byte)197, (byte)  4, (byte) 77, 
	    (byte)233, (byte)119, (byte)240, (byte)219, (byte)147, (byte) 46, (byte)153, (byte)186, 
        (byte) 23, (byte) 54, (byte)241, (byte)187, (byte) 20, (byte)205, (byte) 95, (byte)193,
	    (byte)249, (byte) 24, (byte)101, (byte) 90, (byte)226, (byte) 92, (byte)239, (byte) 33, 
        (byte)129, (byte) 28, (byte) 60, (byte) 66, (byte)139, (byte)  1, (byte)142, (byte) 79,
	    (byte)  5, (byte)132, (byte)  2, (byte)174, (byte)227, (byte)106, (byte)143, (byte)160, 
        (byte)  6, (byte) 11, (byte)237, (byte)152, (byte)127, (byte)212, (byte)211, (byte) 31,
	    (byte)235, (byte) 52, (byte) 44, (byte) 81, (byte)234, (byte)200, (byte) 72, (byte)171, 
        (byte)242, (byte) 42, (byte)104, (byte)162, (byte)253, (byte) 58, (byte)206, (byte)204,
	    (byte)181, (byte)112, (byte) 14, (byte) 86, (byte)  8, (byte) 12, (byte)118, (byte) 18, 
        (byte)191, (byte)114, (byte) 19, (byte) 71, (byte)156, (byte)183, (byte) 93, (byte)135,
	    (byte) 21, (byte)161, (byte)150, (byte) 41, (byte) 16, (byte)123, (byte)154, (byte)199, 
        (byte)243, (byte)145, (byte)120, (byte)111, (byte)157, (byte)158, (byte)178, (byte)177,
	    (byte) 50, (byte)117, (byte) 25, (byte) 61, (byte)255, (byte) 53, (byte)138, (byte)126, 
        (byte)109, (byte) 84, (byte)198, (byte)128, (byte)195, (byte)189, (byte) 13, (byte) 87,
	    (byte)223, (byte)245, (byte) 36, (byte)169, (byte) 62, (byte)168, (byte) 67, (byte)201, 
        (byte)215, (byte)121, (byte)214, (byte)246, (byte)124, (byte) 34, (byte)185, (byte)  3,
	    (byte)224, (byte) 15, (byte)236, (byte)222, (byte)122, (byte)148, (byte)176, (byte)188, 
        (byte)220, (byte)232, (byte) 40, (byte) 80, (byte) 78, (byte) 51, (byte) 10, (byte) 74,
	    (byte)167, (byte)151, (byte) 96, (byte)115, (byte) 30, (byte)  0, (byte) 98, (byte) 68, 
        (byte) 26, (byte)184, (byte) 56, (byte)130, (byte)100, (byte)159, (byte) 38, (byte) 65,
	    (byte)173, (byte) 69, (byte) 70, (byte)146, (byte) 39, (byte) 94, (byte) 85, (byte) 47, 
        (byte)140, (byte)163, (byte)165, (byte)125, (byte)105, (byte)213, (byte)149, (byte) 59,
	    (byte)  7, (byte) 88, (byte)179, (byte) 64, (byte)134, (byte)172, (byte) 29, (byte)247, 
        (byte) 48, (byte) 55, (byte)107, (byte)228, (byte)136, (byte)217, (byte)231, (byte)137,
	    (byte)225, (byte) 27, (byte)131, (byte) 73, (byte) 76, (byte) 63, (byte)248, (byte)254, 
        (byte)141, (byte) 83, (byte)170, (byte)144, (byte)202, (byte)216, (byte)133, (byte) 97,
	    (byte) 32, (byte)113, (byte)103, (byte)164, (byte) 45, (byte) 43, (byte)  9, (byte) 91, 
        (byte)203, (byte)155, (byte) 37, (byte)208, (byte)190, (byte)229, (byte)108, (byte) 82,
	    (byte) 89, (byte)166, (byte)116, (byte)210, (byte)230, (byte)244, (byte)180, (byte)192, 
        (byte)209, (byte)102, (byte)175, (byte)194, (byte) 57, (byte) 75, (byte) 99, (byte)182
    };
    ///////////////////////////////////////////////////////////////////////
    // Обратная таблица подстановок для 128-битного преобразования
    ///////////////////////////////////////////////////////////////////////
    private static final byte[] REVERSE_PI = {
        (byte)0xa5, (byte)0x2d, (byte)0x32, (byte)0x8f, (byte)0x0e, (byte)0x30, (byte)0x38, (byte)0xc0, 
        (byte)0x54, (byte)0xe6, (byte)0x9e, (byte)0x39, (byte)0x55, (byte)0x7e, (byte)0x52, (byte)0x91,
        (byte)0x64, (byte)0x03, (byte)0x57, (byte)0x5a, (byte)0x1c, (byte)0x60, (byte)0x07, (byte)0x18, 
        (byte)0x21, (byte)0x72, (byte)0xa8, (byte)0xd1, (byte)0x29, (byte)0xc6, (byte)0xa4, (byte)0x3f,
        (byte)0xe0, (byte)0x27, (byte)0x8d, (byte)0x0c, (byte)0x82, (byte)0xea, (byte)0xae, (byte)0xb4, 
        (byte)0x9a, (byte)0x63, (byte)0x49, (byte)0xe5, (byte)0x42, (byte)0xe4, (byte)0x15, (byte)0xb7,
        (byte)0xc8, (byte)0x06, (byte)0x70, (byte)0x9d, (byte)0x41, (byte)0x75, (byte)0x19, (byte)0xc9, 
        (byte)0xaa, (byte)0xfc, (byte)0x4d, (byte)0xbf, (byte)0x2a, (byte)0x73, (byte)0x84, (byte)0xd5,
        (byte)0xc3, (byte)0xaf, (byte)0x2b, (byte)0x86, (byte)0xa7, (byte)0xb1, (byte)0xb2, (byte)0x5b, 
        (byte)0x46, (byte)0xd3, (byte)0x9f, (byte)0xfd, (byte)0xd4, (byte)0x0f, (byte)0x9c, (byte)0x2f,
        (byte)0x9b, (byte)0x43, (byte)0xef, (byte)0xd9, (byte)0x79, (byte)0xb6, (byte)0x53, (byte)0x7f, 
        (byte)0xc1, (byte)0xf0, (byte)0x23, (byte)0xe7, (byte)0x25, (byte)0x5e, (byte)0xb5, (byte)0x1e,
        (byte)0xa2, (byte)0xdf, (byte)0xa6, (byte)0xfe, (byte)0xac, (byte)0x22, (byte)0xf9, (byte)0xe2, 
        (byte)0x4a, (byte)0xbc, (byte)0x35, (byte)0xca, (byte)0xee, (byte)0x78, (byte)0x05, (byte)0x6b,
        (byte)0x51, (byte)0xe1, (byte)0x59, (byte)0xa3, (byte)0xf2, (byte)0x71, (byte)0x56, (byte)0x11, 
        (byte)0x6a, (byte)0x89, (byte)0x94, (byte)0x65, (byte)0x8c, (byte)0xbb, (byte)0x77, (byte)0x3c,
        (byte)0x7b, (byte)0x28, (byte)0xab, (byte)0xd2, (byte)0x31, (byte)0xde, (byte)0xc4, (byte)0x5f, 
        (byte)0xcc, (byte)0xcf, (byte)0x76, (byte)0x2c, (byte)0xb8, (byte)0xd8, (byte)0x2e, (byte)0x36,
        (byte)0xdb, (byte)0x69, (byte)0xb3, (byte)0x14, (byte)0x95, (byte)0xbe, (byte)0x62, (byte)0xa1, 
        (byte)0x3b, (byte)0x16, (byte)0x66, (byte)0xe9, (byte)0x5c, (byte)0x6c, (byte)0x6d, (byte)0xad,
        (byte)0x37, (byte)0x61, (byte)0x4b, (byte)0xb9, (byte)0xe3, (byte)0xba, (byte)0xf1, (byte)0xa0, 
        (byte)0x85, (byte)0x83, (byte)0xda, (byte)0x47, (byte)0xc5, (byte)0xb0, (byte)0x33, (byte)0xfa,
        (byte)0x96, (byte)0x6f, (byte)0x6e, (byte)0xc2, (byte)0xf6, (byte)0x50, (byte)0xff, (byte)0x5d, 
        (byte)0xa9, (byte)0x8e, (byte)0x17, (byte)0x1b, (byte)0x97, (byte)0x7d, (byte)0xec, (byte)0x58,
        (byte)0xf7, (byte)0x1f, (byte)0xfb, (byte)0x7c, (byte)0x09, (byte)0x0d, (byte)0x7a, (byte)0x67, 
        (byte)0x45, (byte)0x87, (byte)0xdc, (byte)0xe8, (byte)0x4f, (byte)0x1d, (byte)0x4e, (byte)0x04,
        (byte)0xeb, (byte)0xf8, (byte)0xf3, (byte)0x3e, (byte)0x3d, (byte)0xbd, (byte)0x8a, (byte)0x88, 
        (byte)0xdd, (byte)0xcd, (byte)0x0b, (byte)0x13, (byte)0x98, (byte)0x02, (byte)0x93, (byte)0x80,
        (byte)0x90, (byte)0xd0, (byte)0x24, (byte)0x34, (byte)0xcb, (byte)0xed, (byte)0xf4, (byte)0xce, 
        (byte)0x99, (byte)0x10, (byte)0x44, (byte)0x40, (byte)0x92, (byte)0x3a, (byte)0x01, (byte)0x26,
        (byte)0x12, (byte)0x1a, (byte)0x48, (byte)0x68, (byte)0xf5, (byte)0x81, (byte)0x8b, (byte)0xc7, 
        (byte)0xd6, (byte)0x20, (byte)0x0a, (byte)0x08, (byte)0x00, (byte)0x4c, (byte)0xd7, (byte)0x74
    };
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа (блок 64-бит)
    ////////////////////////////////////////////////////////////////////////////
    public static void test64(IBlockCipher blockCipher) throws Exception
    {
        byte[] key = new byte[] {
            (byte)0xff, (byte)0xee, (byte)0xdd, (byte)0xcc, 
            (byte)0xbb, (byte)0xaa, (byte)0x99, (byte)0x88,
            (byte)0x77, (byte)0x66, (byte)0x55, (byte)0x44, 
            (byte)0x33, (byte)0x22, (byte)0x11, (byte)0x00,
            (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3, 
            (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7,
            (byte)0xf8, (byte)0xf9, (byte)0xfa, (byte)0xfb, 
            (byte)0xfc, (byte)0xfd, (byte)0xfe, (byte)0xff
        };
        byte[] data = new byte[] {
            (byte)0x92, (byte)0xde, (byte)0xf0, (byte)0x6b, 
            (byte)0x3c, (byte)0x13, (byte)0x0a, (byte)0x59,
            (byte)0xdb, (byte)0x54, (byte)0xc7, (byte)0x04, 
            (byte)0xf8, (byte)0x18, (byte)0x9d, (byte)0x20,
            (byte)0x4a, (byte)0x98, (byte)0xfb, (byte)0x2e, 
            (byte)0x67, (byte)0xa8, (byte)0x02, (byte)0x4c,
            (byte)0x89, (byte)0x12, (byte)0x40, (byte)0x9b, 
            (byte)0x17, (byte)0xb5, (byte)0x7e, (byte)0x41
        }; 
        CipherMode modeECB = new CipherMode.ECB(); 
        
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(modeECB))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, new byte[] {
                (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 
                (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10
            }, new byte[] {
                (byte)0x4e, (byte)0xe9, (byte)0x01, (byte)0xe5, 
                (byte)0xc2, (byte)0xd8, (byte)0xca, (byte)0x3d
            });
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x2b, (byte)0x07, (byte)0x3f, (byte)0x04, 
                (byte)0x94, (byte)0xf3, (byte)0x72, (byte)0xa0,            
                (byte)0xde, (byte)0x70, (byte)0xe7, (byte)0x15, 
                (byte)0xd3, (byte)0x55, (byte)0x6e, (byte)0x48,
                (byte)0x11, (byte)0xd8, (byte)0xd9, (byte)0xe9, 
                (byte)0xea, (byte)0xcf, (byte)0xbc, (byte)0x1e,
                (byte)0x7c, (byte)0x68, (byte)0x26, (byte)0x09, 
                (byte)0x96, (byte)0xc6, (byte)0x7e, (byte)0xfb
            });
        }
        CipherMode mode = new CipherMode.CTR(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78
        }, 8); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x4e, (byte)0x98, (byte)0x11, (byte)0x0c, 
                (byte)0x97, (byte)0xb7, (byte)0xb9, (byte)0x3c, 
                (byte)0x3e, (byte)0x25, (byte)0x0d, (byte)0x93, 
                (byte)0xd6, (byte)0xe8, (byte)0x5d, (byte)0x69, 
                (byte)0x13, (byte)0x6d, (byte)0x86, (byte)0x88, 
                (byte)0x07, (byte)0xb2, (byte)0xdb, (byte)0xef, 
                (byte)0x56, (byte)0x8e, (byte)0xb6, (byte)0x80, 
                (byte)0xab, (byte)0x52, (byte)0xa1, (byte)0x2d
            });
        }
        mode = new CipherMode.OFB(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef, 
            (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, 
            (byte)0x0a, (byte)0xbc, (byte)0xde, (byte)0xf1
        }, 8); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0xdb, (byte)0x37, (byte)0xe0, (byte)0xe2, 
                (byte)0x66, (byte)0x90, (byte)0x3c, (byte)0x83,  
                (byte)0x0d, (byte)0x46, (byte)0x64, (byte)0x4c, 
                (byte)0x1f, (byte)0x9a, (byte)0x08, (byte)0x9c, 
                (byte)0xa0, (byte)0xf8, (byte)0x30, (byte)0x62, 
                (byte)0x43, (byte)0x0e, (byte)0x32, (byte)0x7e,
                (byte)0xc8, (byte)0x24, (byte)0xef, (byte)0xb8, 
                (byte)0xbd, (byte)0x4f, (byte)0xdb, (byte)0x05
            });
        }
        mode = new CipherMode.CBC(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef, 
            (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, 
            (byte)0x0a, (byte)0xbc, (byte)0xde, (byte)0xf1, 
            (byte)0x34, (byte)0x56, (byte)0x78, (byte)0x90, 
            (byte)0xab, (byte)0xcd, (byte)0xef, (byte)0x12
        }, 8); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x96, (byte)0xd1, (byte)0xb0, (byte)0x5e, 
                (byte)0xea, (byte)0x68, (byte)0x39, (byte)0x19, 
                (byte)0xaf, (byte)0xf7, (byte)0x61, (byte)0x29, 
                (byte)0xab, (byte)0xb9, (byte)0x37, (byte)0xb9, 
                (byte)0x50, (byte)0x58, (byte)0xb4, (byte)0xa1, 
                (byte)0xc4, (byte)0xbc, (byte)0x00, (byte)0x19, 
                (byte)0x20, (byte)0xb7, (byte)0x8b, (byte)0x1a, 
                (byte)0x7c, (byte)0xd7, (byte)0xe6, (byte)0x67
            });
        }
        mode = new CipherMode.CFB(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef, 
            (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, 
            (byte)0x0a, (byte)0xbc, (byte)0xde, (byte)0xf1
        }, 8); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0xdb, (byte)0x37, (byte)0xe0, (byte)0xe2, 
                (byte)0x66, (byte)0x90, (byte)0x3c, (byte)0x83, 
                (byte)0x0d, (byte)0x46, (byte)0x64, (byte)0x4c, 
                (byte)0x1f, (byte)0x9a, (byte)0x08, (byte)0x9c, 
                (byte)0x24, (byte)0xbd, (byte)0xd2, (byte)0x03, 
                (byte)0x53, (byte)0x15, (byte)0xd3, (byte)0x8b, 
                (byte)0xbc, (byte)0xc0, (byte)0x32, (byte)0x14, 
                (byte)0x21, (byte)0x07, (byte)0x55, (byte)0x05
            });
        }
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(modeECB))
        {
            // создать алгоритм смены ключа для OMAC-ACPKM
            try (KeyDerive keyMeshing = new ACPKM(cipher))
            {
                // указать параметры режима
                CipherMode.CTR ctrParameters = new CipherMode.CTR(
                    new byte[] { 
                       (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78 
                    }, 
                    cipher.blockSize()
                ); 
                // создать режим CBC со специальной сменой ключа
                try (Cipher cipherCTR = new CTR(cipher, ctrParameters, keyMeshing, 16))
                {
                    key = new byte[] {
                        (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                        (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF,
                        (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                        (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                        (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, 
                        (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
                        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                        (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF,
                    }; 
                    data = new byte[] {
                        (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                        (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
                        (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, 
                        (byte)0xBB, (byte)0xAA, (byte)0x99, (byte)0x88,
                        (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                        (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                        (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                        (byte)0xCC, (byte)0xEE, (byte)0xFF, (byte)0x0A,
                        (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                        (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, 
                        (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, 
                        (byte)0xEE, (byte)0xFF, (byte)0x0A, (byte)0x00, 
                        (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, 
                        (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99, 
                    }; 
                    // выполнить тест
                    Cipher.knownTest(cipherCTR, PaddingMode.NONE, key, data, new byte[] {
                        (byte)0x2A, (byte)0xB8, (byte)0x1D, (byte)0xEE, 
                        (byte)0xEB, (byte)0x1E, (byte)0x4C, (byte)0xAB,
                        (byte)0x68, (byte)0xE1, (byte)0x04, (byte)0xC4, 
                        (byte)0xBD, (byte)0x6B, (byte)0x94, (byte)0xEA,
                        (byte)0xC7, (byte)0x2C, (byte)0x67, (byte)0xAF, 
                        (byte)0x6C, (byte)0x2E, (byte)0x5B, (byte)0x6B,
                        (byte)0x0E, (byte)0xAF, (byte)0xB6, (byte)0x17, 
                        (byte)0x70, (byte)0xF1, (byte)0xB3, (byte)0x2E,
                        (byte)0xA1, (byte)0xAE, (byte)0x71, (byte)0x14, 
                        (byte)0x9E, (byte)0xED, (byte)0x13, (byte)0x82, 
                        (byte)0xAB, (byte)0xD4, (byte)0x67, (byte)0x18, 
                        (byte)0x06, (byte)0x72, (byte)0xEC, (byte)0x6F, 
                        (byte)0x84, (byte)0xA2, (byte)0xF1, (byte)0x5B, 
                        (byte)0x3F, (byte)0xCA, (byte)0x72, (byte)0xC1, 
                    });
                }
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа (блок 128-бит)
    ////////////////////////////////////////////////////////////////////////////
    public static void test128(IBlockCipher blockCipher) throws Exception
    {
        byte[] key = new byte[] {
            (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, 
            (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff, 
            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
            (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
            (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10, 
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef
        };
        byte[] data = new byte[] {
            (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
            (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00, 
            (byte)0xff, (byte)0xee, (byte)0xdd, (byte)0xcc, 
            (byte)0xbb, (byte)0xaa, (byte)0x99, (byte)0x88, 
            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
            (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
            (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, 
            (byte)0xcc, (byte)0xee, (byte)0xff, (byte)0x0a, 
            (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
            (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, 
            (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, 
            (byte)0xee, (byte)0xff, (byte)0x0a, (byte)0x00, 
            (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, 
            (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99, 
            (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xee, 
            (byte)0xff, (byte)0x0a, (byte)0x00, (byte)0x11
        }; 
        CipherMode modeECB = new CipherMode.ECB(); 
        
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(modeECB))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, new byte[] {
                (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00, 
                (byte)0xff, (byte)0xee, (byte)0xdd, (byte)0xcc, 
                (byte)0xbb, (byte)0xaa, (byte)0x99, (byte)0x88
            }, new byte[] {
                (byte)0x7f, (byte)0x67, (byte)0x9d, (byte)0x90, 
                (byte)0xbe, (byte)0xbc, (byte)0x24, (byte)0x30, 
                (byte)0x5a, (byte)0x46, (byte)0x8d, (byte)0x42, 
                (byte)0xb9, (byte)0xd4, (byte)0xed, (byte)0xcd
            });
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x7f, (byte)0x67, (byte)0x9d, (byte)0x90, 
                (byte)0xbe, (byte)0xbc, (byte)0x24, (byte)0x30, 
                (byte)0x5a, (byte)0x46, (byte)0x8d, (byte)0x42, 
                (byte)0xb9, (byte)0xd4, (byte)0xed, (byte)0xcd,
                (byte)0xb4, (byte)0x29, (byte)0x91, (byte)0x2c, 
                (byte)0x6e, (byte)0x00, (byte)0x32, (byte)0xf9, 
                (byte)0x28, (byte)0x54, (byte)0x52, (byte)0xd7, 
                (byte)0x67, (byte)0x18, (byte)0xd0, (byte)0x8b, 
                (byte)0xf0, (byte)0xca, (byte)0x33, (byte)0x54, 
                (byte)0x9d, (byte)0x24, (byte)0x7c, (byte)0xee, 
                (byte)0xf3, (byte)0xf5, (byte)0xa5, (byte)0x31, 
                (byte)0x3b, (byte)0xd4, (byte)0xb1, (byte)0x57, 
                (byte)0xd0, (byte)0xb0, (byte)0x9c, (byte)0xcd, 
                (byte)0xe8, (byte)0x30, (byte)0xb9, (byte)0xeb, 
                (byte)0x3a, (byte)0x02, (byte)0xc4, (byte)0xc5, 
                (byte)0xaa, (byte)0x8a, (byte)0xda, (byte)0x98
            });
        }
        CipherMode mode = new CipherMode.CTR(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xce, (byte)0xf0
        }, 16); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0xf1, (byte)0x95, (byte)0xd8, (byte)0xbe, 
                (byte)0xc1, (byte)0x0e, (byte)0xd1, (byte)0xdb, 
                (byte)0xd5, (byte)0x7b, (byte)0x5f, (byte)0xa2, 
                (byte)0x40, (byte)0xbd, (byte)0xa1, (byte)0xb8,
                (byte)0x85, (byte)0xee, (byte)0xe7, (byte)0x33, 
                (byte)0xf6, (byte)0xa1, (byte)0x3e, (byte)0x5d, 
                (byte)0xf3, (byte)0x3c, (byte)0xe4, (byte)0xb3, 
                (byte)0x3c, (byte)0x45, (byte)0xde, (byte)0xe4, 
                (byte)0xa5, (byte)0xea, (byte)0xe8, (byte)0x8b, 
                (byte)0xe6, (byte)0x35, (byte)0x6e, (byte)0xd3, 
                (byte)0xd5, (byte)0xe8, (byte)0x77, (byte)0xf1, 
                (byte)0x35, (byte)0x64, (byte)0xa3, (byte)0xa5, 
                (byte)0xcb, (byte)0x91, (byte)0xfa, (byte)0xb1, 
                (byte)0xf2, (byte)0x0c, (byte)0xba, (byte)0xb6, 
                (byte)0xd1, (byte)0xc6, (byte)0xd1, (byte)0x58, 
                (byte)0x20, (byte)0xbd, (byte)0xba, (byte)0x73
            });
        }
        mode = new CipherMode.OFB(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xce, (byte)0xf0, 
            (byte)0xa1, (byte)0xb2, (byte)0xc3, (byte)0xd4, 
            (byte)0xe5, (byte)0xf0, (byte)0x01, (byte)0x12, 
            (byte)0x23, (byte)0x34, (byte)0x45, (byte)0x56, 
            (byte)0x67, (byte)0x78, (byte)0x89, (byte)0x90, 
            (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, 
            (byte)0x16, (byte)0x17, (byte)0x18, (byte)0x19
        }, 16); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x81, (byte)0x80, (byte)0x0a, (byte)0x59, 
                (byte)0xb1, (byte)0x84, (byte)0x2b, (byte)0x24, 
                (byte)0xff, (byte)0x1f, (byte)0x79, (byte)0x5e, 
                (byte)0x89, (byte)0x7a, (byte)0xbd, (byte)0x95,
                (byte)0xed, (byte)0x5b, (byte)0x47, (byte)0xa7, 
                (byte)0x04, (byte)0x8c, (byte)0xfa, (byte)0xb4, 
                (byte)0x8f, (byte)0xb5, (byte)0x21, (byte)0x36, 
                (byte)0x9d, (byte)0x93, (byte)0x26, (byte)0xbf, 
                (byte)0x66, (byte)0xa2, (byte)0x57, (byte)0xac, 
                (byte)0x3c, (byte)0xa0, (byte)0xb8, (byte)0xb1, 
                (byte)0xc8, (byte)0x0f, (byte)0xe7, (byte)0xfc, 
                (byte)0x10, (byte)0x28, (byte)0x8a, (byte)0x13,  
                (byte)0x20, (byte)0x3e, (byte)0xbb, (byte)0xc0, 
                (byte)0x66, (byte)0x13, (byte)0x86, (byte)0x60, 
                (byte)0xa0, (byte)0x29, (byte)0x22, (byte)0x43, 
                (byte)0xf6, (byte)0x90, (byte)0x31, (byte)0x50
            });
        }
        mode = new CipherMode.CBC(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xce, (byte)0xf0, 
            (byte)0xa1, (byte)0xb2, (byte)0xc3, (byte)0xd4, 
            (byte)0xe5, (byte)0xf0, (byte)0x01, (byte)0x12, 
            (byte)0x23, (byte)0x34, (byte)0x45, (byte)0x56, 
            (byte)0x67, (byte)0x78, (byte)0x89, (byte)0x90, 
            (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, 
            (byte)0x16, (byte)0x17, (byte)0x18, (byte)0x19
        }, 16); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x68, (byte)0x99, (byte)0x72, (byte)0xd4, 
                (byte)0xa0, (byte)0x85, (byte)0xfa, (byte)0x4d, 
                (byte)0x90, (byte)0xe5, (byte)0x2e, (byte)0x3d, 
                (byte)0x6d, (byte)0x7d, (byte)0xcc, (byte)0x27, 
                (byte)0x28, (byte)0x26, (byte)0xe6, (byte)0x61, 
                (byte)0xb4, (byte)0x78, (byte)0xec, (byte)0xa6, 
                (byte)0xaf, (byte)0x1e, (byte)0x8e, (byte)0x44, 
                (byte)0x8d, (byte)0x5e, (byte)0xa5, (byte)0xac, 
                (byte)0xfe, (byte)0x7b, (byte)0xab, (byte)0xf1, 
                (byte)0xe9, (byte)0x19, (byte)0x99, (byte)0xe8, 
                (byte)0x56, (byte)0x40, (byte)0xe8, (byte)0xb0, 
                (byte)0xf4, (byte)0x9d, (byte)0x90, (byte)0xd0, 
                (byte)0x16, (byte)0x76, (byte)0x88, (byte)0x06, 
                (byte)0x5a, (byte)0x89, (byte)0x5c, (byte)0x63, 
                (byte)0x1a, (byte)0x2d, (byte)0x9a, (byte)0x15, 
                (byte)0x60, (byte)0xb6, (byte)0x39, (byte)0x70
            });
        }
        mode = new CipherMode.CFB(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xce, (byte)0xf0, 
            (byte)0xa1, (byte)0xb2, (byte)0xc3, (byte)0xd4, 
            (byte)0xe5, (byte)0xf0, (byte)0x01, (byte)0x12, 
            (byte)0x23, (byte)0x34, (byte)0x45, (byte)0x56, 
            (byte)0x67, (byte)0x78, (byte)0x89, (byte)0x90, 
            (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, 
            (byte)0x16, (byte)0x17, (byte)0x18, (byte)0x19
        }, 16);
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x81, (byte)0x80, (byte)0x0a, (byte)0x59, 
                (byte)0xb1, (byte)0x84, (byte)0x2b, (byte)0x24, 
                (byte)0xff, (byte)0x1f, (byte)0x79, (byte)0x5e, 
                (byte)0x89, (byte)0x7a, (byte)0xbd, (byte)0x95, 
                (byte)0xed, (byte)0x5b, (byte)0x47, (byte)0xa7, 
                (byte)0x04, (byte)0x8c, (byte)0xfa, (byte)0xb4, 
                (byte)0x8f, (byte)0xb5, (byte)0x21, (byte)0x36, 
                (byte)0x9d, (byte)0x93, (byte)0x26, (byte)0xbf, 
                (byte)0x79, (byte)0xf2, (byte)0xa8, (byte)0xeb, 
                (byte)0x5c, (byte)0xc6, (byte)0x8d, (byte)0x38, 
                (byte)0x84, (byte)0x2d, (byte)0x26, (byte)0x4e, 
                (byte)0x97, (byte)0xa2, (byte)0x38, (byte)0xb5,
                (byte)0x4f, (byte)0xfe, (byte)0xbe, (byte)0xcd, 
                (byte)0x4e, (byte)0x92, (byte)0x2d, (byte)0xe6, 
                (byte)0xc7, (byte)0x5b, (byte)0xd9, (byte)0xdd, 
                (byte)0x44, (byte)0xfb, (byte)0xf4, (byte)0xd1
            });
        }
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(modeECB))
        {
            // создать алгоритм смены ключа для OMAC-ACPKM
            try (KeyDerive keyMeshing = new ACPKM(cipher))
            {
                // указать параметры режима
                CipherMode.CTR ctrParameters = new CipherMode.CTR(
                    new byte[] { 
                        (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
                        (byte)0x90, (byte)0xAB, (byte)0xCE, (byte)0xF0 
                    }, 
                    cipher.blockSize()
                ); 
                // создать режим CBC со специальной сменой ключа
                try (Cipher cipherCTR = new CTR(cipher, ctrParameters, keyMeshing, 32))
                {
                    key = new byte[] {
                        (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                        (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF,
                        (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                        (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                        (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, 
                        (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
                        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                        (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF,
                    }; 
                    data = new byte[] {
                        (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                        (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
                        (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, 
                        (byte)0xBB, (byte)0xAA, (byte)0x99, (byte)0x88,
                        (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                        (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                        (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                        (byte)0xCC, (byte)0xEE, (byte)0xFF, (byte)0x0A,
                        (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                        (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, 
                        (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, 
                        (byte)0xEE, (byte)0xFF, (byte)0x0A, (byte)0x00, 
                        (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, 
                        (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99, 
                        (byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xEE, 
                        (byte)0xFF, (byte)0x0A, (byte)0x00, (byte)0x11, 
                        (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, 
                        (byte)0x77, (byte)0x88, (byte)0x99, (byte)0xAA, 
                        (byte)0xBB, (byte)0xCC, (byte)0xEE, (byte)0xFF, 
                        (byte)0x0A, (byte)0x00, (byte)0x11, (byte)0x22, 
                        (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
                        (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                        (byte)0xCC, (byte)0xEE, (byte)0xFF, (byte)0x0A, 
                        (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                        (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, 
                        (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, 
                        (byte)0xEE, (byte)0xFF, (byte)0x0A, (byte)0x00, 
                        (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44,
                    }; 
                    // выполнить тест
                    Cipher.knownTest(cipherCTR, PaddingMode.NONE, key, data, new byte[] {
                        (byte)0xF1, (byte)0x95, (byte)0xD8, (byte)0xBE, 
                        (byte)0xC1, (byte)0x0E, (byte)0xD1, (byte)0xDB,
                        (byte)0xD5, (byte)0x7B, (byte)0x5F, (byte)0xA2, 
                        (byte)0x40, (byte)0xBD, (byte)0xA1, (byte)0xB8,
                        (byte)0x85, (byte)0xEE, (byte)0xE7, (byte)0x33, 
                        (byte)0xF6, (byte)0xA1, (byte)0x3E, (byte)0x5D,
                        (byte)0xF3, (byte)0x3C, (byte)0xE4, (byte)0xB3, 
                        (byte)0x3C, (byte)0x45, (byte)0xDE, (byte)0xE4,
                        (byte)0x4B, (byte)0xCE, (byte)0xEB, (byte)0x8F, 
                        (byte)0x64, (byte)0x6F, (byte)0x4C, (byte)0x55, 
                        (byte)0x00, (byte)0x17, (byte)0x06, (byte)0x27, 
                        (byte)0x5E, (byte)0x85, (byte)0xE8, (byte)0x00, 
                        (byte)0x58, (byte)0x7C, (byte)0x4D, (byte)0xF5, 
                        (byte)0x68, (byte)0xD0, (byte)0x94, (byte)0x39, 
                        (byte)0x3E, (byte)0x48, (byte)0x34, (byte)0xAF, 
                        (byte)0xD0, (byte)0x80, (byte)0x50, (byte)0x46, 
                        (byte)0xCF, (byte)0x30, (byte)0xF5, (byte)0x76, 
                        (byte)0x86, (byte)0xAE, (byte)0xEC, (byte)0xE1, 
                        (byte)0x1C, (byte)0xFC, (byte)0x6C, (byte)0x31, 
                        (byte)0x6B, (byte)0x8A, (byte)0x89, (byte)0x6E, 
                        (byte)0xDF, (byte)0xFD, (byte)0x07, (byte)0xEC, 
                        (byte)0x81, (byte)0x36, (byte)0x36, (byte)0x46, 
                        (byte)0x0C, (byte)0x4F, (byte)0x3B, (byte)0x74, 
                        (byte)0x34, (byte)0x23, (byte)0x16, (byte)0x3E, 
                        (byte)0x64, (byte)0x09, (byte)0xA9, (byte)0xC2, 
                        (byte)0x82, (byte)0xFA, (byte)0xC8, (byte)0xD4, 
                        (byte)0x69, (byte)0xD2, (byte)0x21, (byte)0xE7, 
                        (byte)0xFB, (byte)0xD6, (byte)0xDE, (byte)0x5D, 
                    });
                }
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // GOSTR3412-MAC 
    ////////////////////////////////////////////////////////////////////////////
    public static void testMAC64(IBlockCipher blockCipher) throws Exception
    {
        // указать начальную синхропосылку
        byte[] start = new byte[blockCipher.blockSize()]; 
        
        // создать алгоритм выработки имитовставки
        try (Mac macAlgorithm = aladdin.capi.mac.OMAC1.create(blockCipher, start))
        {
            Mac.knownTest(macAlgorithm, new byte[] {
                (byte)0xff, (byte)0xee, (byte)0xdd, (byte)0xcc, 
                (byte)0xbb, (byte)0xaa, (byte)0x99, (byte)0x88,
                (byte)0x77, (byte)0x66, (byte)0x55, (byte)0x44, 
                (byte)0x33, (byte)0x22, (byte)0x11, (byte)0x00,
                (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3, 
                (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7,
                (byte)0xf8, (byte)0xf9, (byte)0xfa, (byte)0xfb, 
                (byte)0xfc, (byte)0xfd, (byte)0xfe, (byte)0xff
            }, 1, new byte[] {
                (byte)0x92, (byte)0xde, (byte)0xf0, (byte)0x6b, 
                (byte)0x3c, (byte)0x13, (byte)0x0a, (byte)0x59,
                (byte)0xdb, (byte)0x54, (byte)0xc7, (byte)0x04, 
                (byte)0xf8, (byte)0x18, (byte)0x9d, (byte)0x20,
                (byte)0x4a, (byte)0x98, (byte)0xfb, (byte)0x2e, 
                (byte)0x67, (byte)0xa8, (byte)0x02, (byte)0x4c,
                (byte)0x89, (byte)0x12, (byte)0x40, (byte)0x9b, 
                (byte)0x17, (byte)0xb5, (byte)0x7e, (byte)0x41
            }, new byte[] {
                (byte)0x15, (byte)0x4e, (byte)0x72, (byte)0x10            
            });
        }
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.ECB()))
        {
            // создать алгоритм выработки имитовставки
            try (Mac macAlgorithm = GOSTR3412ACPKM.create(cipher, 16, 80, 8))
            {
                byte[] key = new byte[] {
                    (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                    (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF,
                    (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                    (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                    (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, 
                    (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
                    (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                    (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF,
                }; 
                Mac.knownTest(macAlgorithm, key, 1, new byte[] {
                    (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                    (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
                    (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, 
                }, new byte[] {
                    (byte)0xA0, (byte)0x54, (byte)0x0E, (byte)0x37,             
                    (byte)0x30, (byte)0xAC, (byte)0xBC, (byte)0xF3,             
                });
                Mac.knownTest(macAlgorithm, key, 1, new byte[] {
                    (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                    (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
                    (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, 
                    (byte)0xBB, (byte)0xAA, (byte)0x99, (byte)0x88, 
                    (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                    (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
                    (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                    (byte)0xCC, (byte)0xEE, (byte)0xFF, (byte)0x0A, 
                    (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                    (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, 
                }, new byte[] {
                    (byte)0x34, (byte)0x00, (byte)0x8D, (byte)0xAD,             
                    (byte)0x54, (byte)0x96, (byte)0xBB, (byte)0x8E,             
                });
            }
        }
    }
    public static void testMAC128(IBlockCipher blockCipher) throws Exception
    {
        // указать начальную синхропосылку
        byte[] start = new byte[blockCipher.blockSize()]; 
        
        // создать алгоритм выработки имитовставки
        try (Mac macAlgorithm = aladdin.capi.mac.OMAC1.create(blockCipher, start))
        {
            Mac.knownTest(macAlgorithm, new byte[] {
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, 
                (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff, 
                (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
                (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 
                (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10, 
                (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef
            }, 1, new byte[] {
                (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00, 
                (byte)0xff, (byte)0xee, (byte)0xdd, (byte)0xcc, 
                (byte)0xbb, (byte)0xaa, (byte)0x99, (byte)0x88, 
                (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, 
                (byte)0xcc, (byte)0xee, (byte)0xff, (byte)0x0a, 
                (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, 
                (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, 
                (byte)0xee, (byte)0xff, (byte)0x0a, (byte)0x00, 
                (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, 
                (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99, 
                (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xee, 
                (byte)0xff, (byte)0x0a, (byte)0x00, (byte)0x11
            }, new byte[] {
                (byte)0x33, (byte)0x6f, (byte)0x4d, (byte)0x29, 
                (byte)0x60, (byte)0x59, (byte)0xfb, (byte)0xe3
            });
        }
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.ECB()))
        {
            // создать алгоритм выработки имитовставки
            try (Mac macAlgorithm = GOSTR3412ACPKM.create(cipher, 32, 96, 16))
            {
                byte[] key = new byte[] {
                    (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                    (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF,
                    (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                    (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                    (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, 
                    (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
                    (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                    (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF,
                }; 
                Mac.knownTest(macAlgorithm, key, 1, new byte[] {
                    (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                    (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
                    (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, 
                    (byte)0xBB, (byte)0xAA, (byte)0x99, (byte)0x88, 
                    (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                    (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                }, new byte[] {
                    (byte)0xB5, (byte)0x36, (byte)0x7F, (byte)0x47,             
                    (byte)0xB6, (byte)0x2B, (byte)0x99, (byte)0x5E,             
                    (byte)0xEB, (byte)0x2A, (byte)0x64, (byte)0x8C,             
                    (byte)0x58, (byte)0x43, (byte)0x14, (byte)0x5E,             
                });
                Mac.knownTest(macAlgorithm, key, 1, new byte[] {
                    (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                    (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
                    (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, 
                    (byte)0xBB, (byte)0xAA, (byte)0x99, (byte)0x88, 
                    (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                    (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
                    (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                    (byte)0xCC, (byte)0xEE, (byte)0xFF, (byte)0x0A, 
                    (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                    (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, 
                    (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, 
                    (byte)0xEE, (byte)0xFF, (byte)0x0A, (byte)0x00, 
                    (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, 
                    (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99, 
                    (byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xEE, 
                    (byte)0xFF, (byte)0x0A, (byte)0x00, (byte)0x11,  
                    (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, 
                    (byte)0x77, (byte)0x88, (byte)0x99, (byte)0xAA, 
                    (byte)0xBB, (byte)0xCC, (byte)0xEE, (byte)0xFF, 
                    (byte)0x0A, (byte)0x00, (byte)0x11, (byte)0x22,
                }, new byte[] {
                    (byte)0xFB, (byte)0xB8, (byte)0xDC, (byte)0xEE,             
                    (byte)0x45, (byte)0xBE, (byte)0xA6, (byte)0x7C,             
                    (byte)0x35, (byte)0xF5, (byte)0x8C, (byte)0x57,             
                    (byte)0x00, (byte)0x89, (byte)0x8E, (byte)0x5D,             
                });
            }
        }
    }
}
