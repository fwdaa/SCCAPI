package aladdin.capi.gost.hash;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.gost.*; 
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования ГОСТ Р 34.11-1994
///////////////////////////////////////////////////////////////////////////
public class GOSTR3411_1994 extends BlockHash
{
    // хэш-значение производителей от пустых данных с тестовой таблицей 
    public static final byte[] ZERO_HASH_VENDORS_TEST = new byte[] {
        (byte)0xce, (byte)0x85, (byte)0xb9, (byte)0x9c, 
        (byte)0xc4, (byte)0x67, (byte)0x52, (byte)0xff, 
        (byte)0xfe, (byte)0xe3, (byte)0x5c, (byte)0xab, 
        (byte)0x9a, (byte)0x7b, (byte)0x02, (byte)0x78, 
        (byte)0xab, (byte)0xb4, (byte)0xc2, (byte)0xd2, 
        (byte)0x05, (byte)0x5c, (byte)0xff, (byte)0x68, 
        (byte)0x5a, (byte)0xf4, (byte)0x91, (byte)0x2c, 
        (byte)0x49, (byte)0x49, (byte)0x0f, (byte)0x8d
    }; 
    // хэш-значение по стандарту от пустых данных с тестовой таблицей 
    public static final byte[] ZERO_HASH_COMPAT_TEST = new byte[] {
    	(byte)0x89, (byte)0x1d, (byte)0x35, (byte)0x8a, 
        (byte)0x84, (byte)0xc6, (byte)0x03, (byte)0x3c, 
		(byte)0xf1, (byte)0x7b, (byte)0xac, (byte)0x82, 
        (byte)0xd7, (byte)0x7b, (byte)0xb5, (byte)0xd6, 
		(byte)0x79, (byte)0x16, (byte)0x95, (byte)0xa0, 
        (byte)0x8f, (byte)0xfc, (byte)0xe3, (byte)0x76, 
		(byte)0x8d, (byte)0x39, (byte)0xfb, (byte)0xca, 
        (byte)0xcf, (byte)0x8b, (byte)0x29, (byte)0xbd
    }; 
    // хэш-значение производителей от пустых данных с таблицей RFC 4357
    public static final byte[] ZERO_HASH_VENDORS_CP = new byte[] {
        (byte)0x98, (byte)0x1e, (byte)0x5f, (byte)0x3c, 
        (byte)0xa3, (byte)0x0c, (byte)0x84, (byte)0x14, 
        (byte)0x87, (byte)0x83, (byte)0x0f, (byte)0x84, 
        (byte)0xfb, (byte)0x43, (byte)0x3e, (byte)0x13, 
        (byte)0xac, (byte)0x11, (byte)0x01, (byte)0x56, 
        (byte)0x9b, (byte)0x9c, (byte)0x13, (byte)0x58, 
        (byte)0x4a, (byte)0xc4, (byte)0x83, (byte)0x23, 
        (byte)0x4c, (byte)0xd6, (byte)0x56, (byte)0xc0        
    }; 
    // хэш-значение по стандарту от пустых данных с таблицей RFC 4357
    public static final byte[] ZERO_HASH_COMPAT_CP = new byte[] {
	    (byte)0x3f, (byte)0x25, (byte)0xbc, (byte)0x1f, 
        (byte)0xbb, (byte)0xce, (byte)0x27, (byte)0xca,
	    (byte)0x10, (byte)0xfb, (byte)0x19, (byte)0x58, 
        (byte)0xf3, (byte)0x19, (byte)0x47, (byte)0x3a,
	    (byte)0xe7, (byte)0xe1, (byte)0x74, (byte)0x82, 
        (byte)0xc3, (byte)0xb5, (byte)0x3e, (byte)0xcf,
	    (byte)0x47, (byte)0xa7, (byte)0xe2, (byte)0xde, 
        (byte)0x8a, (byte)0xab, (byte)0xe4, (byte)0xc8
    }; 
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
	///////////////////////////////////////////////////////////////////////////
	// Используемые константы
	///////////////////////////////////////////////////////////////////////////
	private static final byte[] C2 = {
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
	};
	private static final byte[] C3 = {
		(byte)0x00, (byte)0xFF, (byte)0x00, (byte)0xFF,
		(byte)0x00, (byte)0xFF, (byte)0x00, (byte)0xFF,
		(byte)0xFF, (byte)0x00, (byte)0xFF, (byte)0x00,
		(byte)0xFF, (byte)0x00, (byte)0xFF, (byte)0x00,
		(byte)0x00, (byte)0xFF, (byte)0xFF, (byte)0x00,
		(byte)0xFF, (byte)0x00, (byte)0x00, (byte)0xFF,
		(byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0xFF
	};
	private static final byte[] C4 = {
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
	};
	private static final byte[][] C = { C2, C3, C4 };

	///////////////////////////////////////////////////////////////////////////
	// x3 || x2 || x1 || x0 ==> x0 ^ x1 || x3 || x2 || x1
	///////////////////////////////////////////////////////////////////////////
	private static void A(byte[] x)
	{
		// выделить вспомогательный буфер
		byte[] a = new byte[8];

		// вычислить a = x0 ^ x1
		for(int j = 0; j < 8; j++)
		{
			// поразрядно сложить x0 и x1
			a[j] = (byte)(x[j] ^ x[j + 8]);
		}
		// сдвинуть 64-разрядные слова на одну позицию
		System.arraycopy(x, 8, x, 0, 3 * 8);

		// изменить значение разряда
		System.arraycopy(a, 0, x, 3 * 8, 8);
	}
	///////////////////////////////////////////////////////////////////////////
	// n16 || .. || n1 ==> n1 ^ n2 ^ n3 ^ n4 ^ n13 ^ n16 || n16 || .. || n2
	///////////////////////////////////////////////////////////////////////////
	private static void FW(byte[] S)
	{
		// выделить вспомогательные буферы
		short[] wS = new short[16]; short[] vS = new short[16];

		// для всех пар байтов
		for (int i = 0; i < S.length / 2; i++)
		{
            // преобразовать пару байтов в 16-разрядное слово
			wS[i] = Convert.toInt16(S, i * 2, ENDIAN); 
		}
		// сдвинуть 16-разрядные слова на одну позицию
		System.arraycopy(wS, 1, vS, 0, 16 - 1);

		// изменить значение разряда
		vS[15] = (short)(wS[0] ^ wS[1] ^ wS[2] ^ wS[3] ^ wS[12] ^ wS[15]);

		// для всех пар байтов
		for (int i = 0; i < vS.length; i++)
		{
			// извлечь отдельные байты
            Convert.fromInt16(vS[i], ENDIAN, S, i * 2);
		}
	}
 	///////////////////////////////////////////////////////////////////////////
	// Используемое шифрование
	///////////////////////////////////////////////////////////////////////////
	private static void E(Cipher gost28147, byte[] W, 
		byte[] src, int srcOff, byte[] dest, int destOff) throws IOException
	{
		// создать временный буфер для ключа
		byte[] K = new byte[32];

		// создать ключ для шифрования
		for (int k = 0; k < 8; k++)
		{
			K[4 * k + 0] = W[k +  0]; K[4 * k + 1] = W[k +  8];
			K[4 * k + 2] = W[k + 16]; K[4 * k + 3] = W[k + 24];
		}
        // создать ключ шифрования
        try (ISecretKey key = gost28147.keyFactory().create(K))
        {
            // зашифровать в режиме простой замены
            gost28147.encrypt(key, PaddingMode.NONE, src, srcOff, 8, dest, destOff);
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
	}
	///////////////////////////////////////////////////////////////////////////
	// Конструктор
	///////////////////////////////////////////////////////////////////////////
    private final Cipher  gost28147; // алгоритм шифрования блока
	private final byte[]  start;     // стартовое хэш-значение
	private final byte[]  hash;      // текущее хэш-значение
	private final byte[]  sum;		 // аккумулятор
    private final boolean compat;    // признак совместимости со стандартом 
	private       long    length; 	 // размер данных

	// конструктор
	public GOSTR3411_1994(Cipher gost28147, byte[] start, boolean compat) 
	{ 
		// сохранить переданные параметры
		this.gost28147 = RefObject.addRef(gost28147); this.start = start;  

		// выделить память для текущего хэш-значения
		hash = new byte[blockSize()]; sum = new byte[blockSize()]; this.compat = compat; 
	}
	// конструктор
	public GOSTR3411_1994(byte[] sbox, byte[] start, boolean compat) 
	{ 
		// сохранить переданные параметры
		this.gost28147 = new aladdin.capi.gost.engine.GOST28147(sbox); this.start = start;  

		// выделить память для текущего хэш-значения
		hash = new byte[blockSize()]; sum = new byte[blockSize()]; this.compat = compat; 
	}
    // освободить ресурсы
    @Override protected void onClose() throws IOException    
    {
        // освободить ресурсы
        RefObject.release(gost28147); super.onClose();
    }
	// размер блока алгоритма хэширования
	@Override public final int blockSize() { return 32; }

    // размер хэш-значения в байтах
	@Override public final int hashSize() { return 32; }

	///////////////////////////////////////////////////////////////////////////
	// Обработка одного блока
	///////////////////////////////////////////////////////////////////////////
	private void processBlock(byte[] src, int srcOff) throws IOException 
	{
		// выделить вспомогательные буферы
		byte[] U = new byte[32]; byte[] V = new byte[32];
		byte[] W = new byte[32]; byte[] S = new byte[32];

		// установить переменные U и V
		System.arraycopy(hash,     0, U, 0, 32);
		System.arraycopy(src, srcOff, V, 0, 32);

		//////////////////////// выполнить шаг 1 //////////////////////////

        // сложить поразрядно U и V
		for (int j = 0; j < 32; j++) W[j] = (byte)(U[j] ^ V[j]);

		// зашифровать часть хэш-значения
		E(gost28147, W, hash, 0, S, 0);

		//////////////////////// выполнить шаги 2, 3, 4 ///////////////////
		for (int i = 1; i < 4; i++)
		{
			A(U); // выполнить преобразование A над U

			// сложить поразрядно U с константой
			for (int j = 0; j < 32; j++) U[j] ^= C[i - 1][j];

			A(V); A(V); // выполнить 2 преобразования A над V

			// сложить поразрядно U и V
			for (int j = 0; j < 32; j++) W[j] = (byte)(U[j] ^ V[j]);

			// зашифровать часть хэш-значения
			E(gost28147, W, hash, i * 32 / 4, S, i * 32 / 4);
		}
		//////////////////////// выполнить последние шаги /////////////////

		// выполнить 12 преобразований fw над S
		for (int n = 0; n < 12; n++) FW(S);

		// сложить поразрядно S и блок данных
		for (int j = 0; j < 32; j++) S[j] ^= src[srcOff + j];

		FW(S); // выполнить преобразование fw над S

		// сложить поразрядно S и текущее хэш-значение
		for (int j = 0; j < 32; j++) S[j] ^= hash[j];

		// выполнить 61 преобразование fw над S
		for (int n = 0; n < 61; n++) FW(S);

		// переустановить текущее хэш-значение
		System.arraycopy(S, 0, hash, 0, 32);
	}
	///////////////////////////////////////////////////////////////////////////
	// Вычислить хэш-значение
	///////////////////////////////////////////////////////////////////////////
	@Override public void init() throws IOException
	{
		// скопировать стартовое хэш-значение
		super.init(); System.arraycopy(start, 0, this.hash, 0, 32); 

		// обнулить аккумулятор
		for (int i = 0; i < sum.length; i++) sum[i] = 0; length = 0; 
	}
	@Override protected void update(byte[] data, int dataOff) throws IOException
	{
		// выполнить сложение по модулю 2^{256}
		int carry = 0; for (int i = 0; i < 32; i++)
		{
			// выполнить сложение по модулю 2^{8}
			int accumulator = (sum[i] & 0xFF) + (data[dataOff + i] & 0xFF) + carry;

			// учесть бит перноса в старший разряд
			sum[i] = (byte)accumulator; carry = accumulator >> 8;
		}
		// обработать полный блок
		processBlock(data, dataOff); length += 32; 
	}
	@Override protected void finish(byte[] data, 
        int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
	{
		// выделить память для блока
        int blockSize = blockSize(); byte[] buffer = new byte[blockSize]; 

        // скопировать данные
        System.arraycopy(data, dataOff, buffer, 0, dataLen); 
        
        // при наличии данных
        if (length + dataLen != 0 || compat)
        {
            // дополнить неполный блок нулями
            for (int i = dataLen; i < blockSize; i++) buffer[i] = 0;

            // обработать неполный блок
            update(buffer, 0); length -= blockSize - dataLen; 
        }
		// закодировать размер всех данных в битах
        Convert.fromInt64(length * 8, ENDIAN, buffer, 0); 
        
		// дополнить блок нулями
		for (int i = 8; i < blockSize; i++) buffer[i] = 0;

		// обработать размер и контрольную сумму всех данных в битах
		processBlock(buffer, 0); processBlock(sum, 0);

		// вернуть результат
		System.arraycopy(hash, 0, buf, bufOff, 32); 
	}
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void testTest(Hash algorithm) throws Exception
    {
        knownTest(algorithm, 1, new byte[] {
            (byte)0x54, (byte)0x68, (byte)0x69, (byte)0x73,
            (byte)0x20, (byte)0x69, (byte)0x73, (byte)0x20,
            (byte)0x6D, (byte)0x65, (byte)0x73, (byte)0x73,
            (byte)0x61, (byte)0x67, (byte)0x65, (byte)0x2C,
            (byte)0x20, (byte)0x6C, (byte)0x65, (byte)0x6E,
            (byte)0x67, (byte)0x74, (byte)0x68, (byte)0x3D,
            (byte)0x33, (byte)0x32, (byte)0x20, (byte)0x62,
            (byte)0x79, (byte)0x74, (byte)0x65, (byte)0x73
        }, new byte[] { 
            (byte)0xB1, (byte)0xC4, (byte)0x66, (byte)0xD3,
            (byte)0x75, (byte)0x19, (byte)0xB8, (byte)0x2E,
            (byte)0x83, (byte)0x19, (byte)0x81, (byte)0x9F,
            (byte)0xF3, (byte)0x25, (byte)0x95, (byte)0xE0,
            (byte)0x47, (byte)0xA2, (byte)0x8C, (byte)0xB6,
            (byte)0xF8, (byte)0x3E, (byte)0xFF, (byte)0x1C,
            (byte)0x69, (byte)0x16, (byte)0xA8, (byte)0x15,
            (byte)0xA6, (byte)0x37, (byte)0xFF, (byte)0xFA
        });
        knownTest(algorithm, 1, new byte[] {
            (byte)0x53, (byte)0x75, (byte)0x70, (byte)0x70,
            (byte)0x6F, (byte)0x73, (byte)0x65, (byte)0x20,
            (byte)0x74, (byte)0x68, (byte)0x65, (byte)0x20,
            (byte)0x6F, (byte)0x72, (byte)0x69, (byte)0x67,
            (byte)0x69, (byte)0x6E, (byte)0x61, (byte)0x6C,
            (byte)0x20, (byte)0x6D, (byte)0x65, (byte)0x73,
            (byte)0x73, (byte)0x61, (byte)0x67, (byte)0x65,
            (byte)0x20, (byte)0x68, (byte)0x61, (byte)0x73,
            (byte)0x20, (byte)0x6C, (byte)0x65, (byte)0x6E,
            (byte)0x67, (byte)0x74, (byte)0x68, (byte)0x20,
            (byte)0x3D, (byte)0x20, (byte)0x35, (byte)0x30,
            (byte)0x20, (byte)0x62, (byte)0x79, (byte)0x74,
            (byte)0x65, (byte)0x73,
        }, new byte[] { 
            (byte)0x47, (byte)0x1A, (byte)0xBA, (byte)0x57,
            (byte)0xA6, (byte)0x0A, (byte)0x77, (byte)0x0D,
            (byte)0x3A, (byte)0x76, (byte)0x13, (byte)0x06,
            (byte)0x35, (byte)0xC1, (byte)0xFB, (byte)0xEA,
            (byte)0x4E, (byte)0xF1, (byte)0x4D, (byte)0xE5,
            (byte)0x1F, (byte)0x78, (byte)0xB4, (byte)0xAE,
            (byte)0x57, (byte)0xDD, (byte)0x89, (byte)0x3B,
            (byte)0x62, (byte)0xF5, (byte)0x52, (byte)0x08
        });
        knownTest(algorithm, 1, 
            "a", new byte[] { 
            (byte)0xd4, (byte)0x2c, (byte)0x53, (byte)0x9e, 
            (byte)0x36, (byte)0x7c, (byte)0x66, (byte)0xe9, 
            (byte)0xc8, (byte)0x8a, (byte)0x80, (byte)0x1f, 
            (byte)0x66, (byte)0x49, (byte)0x34, (byte)0x9c, 
            (byte)0x21, (byte)0x87, (byte)0x1b, (byte)0x43, 
            (byte)0x44, (byte)0xc6, (byte)0xa5, (byte)0x73, 
            (byte)0xf8, (byte)0x49, (byte)0xfd, (byte)0xce, 
            (byte)0x62, (byte)0xf3, (byte)0x14, (byte)0xdd
        });
        knownTest(algorithm, 1, 
            "abc", new byte[] { 
            (byte)0xf3, (byte)0x13, (byte)0x43, (byte)0x48, 
            (byte)0xc4, (byte)0x4f, (byte)0xb1, (byte)0xb2, 
            (byte)0xa2, (byte)0x77, (byte)0x72, (byte)0x9e, 
            (byte)0x22, (byte)0x85, (byte)0xeb, (byte)0xb5, 
            (byte)0xcb, (byte)0x5e, (byte)0x0f, (byte)0x29, 
            (byte)0xc9, (byte)0x75, (byte)0xbc, (byte)0x75, 
            (byte)0x3b, (byte)0x70, (byte)0x49, (byte)0x7c, 
            (byte)0x06, (byte)0xa4, (byte)0xd5, (byte)0x1d
        });
        knownTest(algorithm, 1, 
            "message digest", new byte[] { 
            (byte)0xad, (byte)0x44, (byte)0x34, (byte)0xec, 
            (byte)0xb1, (byte)0x8f, (byte)0x2c, (byte)0x99, 
            (byte)0xb6, (byte)0x0c, (byte)0xbe, (byte)0x59, 
            (byte)0xec, (byte)0x3d, (byte)0x24, (byte)0x69, 
            (byte)0x58, (byte)0x2b, (byte)0x65, (byte)0x27, 
            (byte)0x3f, (byte)0x48, (byte)0xde, (byte)0x72, 
            (byte)0xdb, (byte)0x2f, (byte)0xde, (byte)0x16, 
            (byte)0xa4, (byte)0x88, (byte)0x9a, (byte)0x4d
        });
        knownTest(algorithm, 1, 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + 
            "abcdefghijklmnopqrstuvwxyz0123456789", new byte[] { 
            (byte)0x95, (byte)0xc1, (byte)0xaf, (byte)0x62, 
            (byte)0x7c, (byte)0x35, (byte)0x64, (byte)0x96, 
            (byte)0xd8, (byte)0x02, (byte)0x74, (byte)0x33, 
            (byte)0x0b, (byte)0x2c, (byte)0xff, (byte)0x6a, 
            (byte)0x10, (byte)0xc6, (byte)0x7b, (byte)0x5f, 
            (byte)0x59, (byte)0x70, (byte)0x87, (byte)0x20, 
            (byte)0x2f, (byte)0x94, (byte)0xd0, (byte)0x6d, 
            (byte)0x23, (byte)0x38, (byte)0xcf, (byte)0x8e
        });
        knownTest(algorithm, 1, 
            "1234567890123456789012345678901234567890" + 
            "1234567890123456789012345678901234567890", new byte[] { 
            (byte)0xcc, (byte)0x17, (byte)0x8d, (byte)0xca, 
            (byte)0xd4, (byte)0xdf, (byte)0x61, (byte)0x9d, 
            (byte)0xca, (byte)0xa0, (byte)0x0a, (byte)0xac, 
            (byte)0x79, (byte)0xca, (byte)0x35, (byte)0x5c, 
            (byte)0x00, (byte)0x14, (byte)0x4e, (byte)0x4a, 
            (byte)0xda, (byte)0x27, (byte)0x93, (byte)0xd7, 
            (byte)0xbd, (byte)0x9b, (byte)0x35, (byte)0x18, 
            (byte)0xea, (byte)0xd3, (byte)0xcc, (byte)0xd3
        });
        knownTest(algorithm, 1, 
            "This is message, length=32 bytes", new byte[] { 
            (byte)0xb1, (byte)0xc4, (byte)0x66, (byte)0xd3, 
            (byte)0x75, (byte)0x19, (byte)0xb8, (byte)0x2e, 
            (byte)0x83, (byte)0x19, (byte)0x81, (byte)0x9f, 
            (byte)0xf3, (byte)0x25, (byte)0x95, (byte)0xe0, 
            (byte)0x47, (byte)0xa2, (byte)0x8c, (byte)0xb6, 
            (byte)0xf8, (byte)0x3e, (byte)0xff, (byte)0x1c, 
            (byte)0x69, (byte)0x16, (byte)0xa8, (byte)0x15, 
            (byte)0xa6, (byte)0x37, (byte)0xff, (byte)0xfa
        });
        knownTest(algorithm, 1, 
            "Suppose the original message has length = 50 bytes", new byte[] { 
            (byte)0x47, (byte)0x1a, (byte)0xba, (byte)0x57, 
            (byte)0xa6, (byte)0x0a, (byte)0x77, (byte)0x0d, 
            (byte)0x3a, (byte)0x76, (byte)0x13, (byte)0x06, 
            (byte)0x35, (byte)0xc1, (byte)0xfb, (byte)0xea, 
            (byte)0x4e, (byte)0xf1, (byte)0x4d, (byte)0xe5, 
            (byte)0x1f, (byte)0x78, (byte)0xb4, (byte)0xae, 
            (byte)0x57, (byte)0xdd, (byte)0x89, (byte)0x3b, 
            (byte)0x62, (byte)0xf5, (byte)0x52, (byte)0x08
        });
        knownTest(algorithm, 128, 
            "U", new byte[] { 
            (byte)0x53, (byte)0xa3, (byte)0xa3, (byte)0xed, 
            (byte)0x25, (byte)0x18, (byte)0x0c, (byte)0xef, 
            (byte)0x0c, (byte)0x1d, (byte)0x85, (byte)0xa0, 
            (byte)0x74, (byte)0x27, (byte)0x3e, (byte)0x55, 
            (byte)0x1c, (byte)0x25, (byte)0x66, (byte)0x0a, 
            (byte)0x87, (byte)0x06, (byte)0x2a, (byte)0x52, 
            (byte)0xd9, (byte)0x26, (byte)0xa9, (byte)0xe8, 
            (byte)0xfe, (byte)0x57, (byte)0x33, (byte)0xa4
        });
/*       
        knownTest(algorithm, 1000000, 
            "a", new byte[] { 
            (byte)0x5c, (byte)0x00, (byte)0xcc, (byte)0xc2, 
            (byte)0x73, (byte)0x4c, (byte)0xdd, (byte)0x33, 
            (byte)0x32, (byte)0xd3, (byte)0xd4, (byte)0x74, 
            (byte)0x95, (byte)0x76, (byte)0xe3, (byte)0xc1, 
            (byte)0xa7, (byte)0xdb, (byte)0xaf, (byte)0x0e, 
            (byte)0x7e, (byte)0xa7, (byte)0x4e, (byte)0x9f, 
            (byte)0xa6, (byte)0x02, (byte)0x41, (byte)0x3c, 
            (byte)0x90, (byte)0xa1, (byte)0x29, (byte)0xfa
        });
*/
        knownTest(algorithm, 1, 
            "The quick brown fox jumps over the lazy dog", new byte[] { 
            (byte)0x77, (byte)0xb7, (byte)0xfa, (byte)0x41, 
            (byte)0x0c, (byte)0x9a, (byte)0xc5, (byte)0x8a, 
            (byte)0x25, (byte)0xf4, (byte)0x9b, (byte)0xca, 
            (byte)0x7d, (byte)0x04, (byte)0x68, (byte)0xc9, 
            (byte)0x29, (byte)0x65, (byte)0x29, (byte)0x31, 
            (byte)0x5e, (byte)0xac, (byte)0xa7, (byte)0x6b, 
            (byte)0xd1, (byte)0xa1, (byte)0x0f, (byte)0x37, 
            (byte)0x6d, (byte)0x1f, (byte)0x42, (byte)0x94
        });
        knownTest(algorithm, 1, 
            "The quick brown fox jumps over the lazy cog", new byte[] { 
            (byte)0xa3, (byte)0xeb, (byte)0xc4, (byte)0xda, 
            (byte)0xaa, (byte)0xb7, (byte)0x8b, (byte)0x0b, 
            (byte)0xe1, (byte)0x31, (byte)0xda, (byte)0xb5, 
            (byte)0x73, (byte)0x7a, (byte)0x7f, (byte)0x67, 
            (byte)0xe6, (byte)0x02, (byte)0x67, (byte)0x0d, 
            (byte)0x54, (byte)0x35, (byte)0x21, (byte)0x31, 
            (byte)0x91, (byte)0x50, (byte)0xd2, (byte)0xe1, 
            (byte)0x4e, (byte)0xee, (byte)0xc4, (byte)0x45
        });
    }
    public static void testPro(Hash algorithm) throws Exception
    {
        knownTest(algorithm, 1, 
            "a", new byte[] { 
            (byte)0xe7, (byte)0x4c, (byte)0x52, (byte)0xdd, 
            (byte)0x28, (byte)0x21, (byte)0x83, (byte)0xbf, 
            (byte)0x37, (byte)0xaf, (byte)0x00, (byte)0x79, 
            (byte)0xc9, (byte)0xf7, (byte)0x80, (byte)0x55, 
            (byte)0x71, (byte)0x5a, (byte)0x10, (byte)0x3f, 
            (byte)0x17, (byte)0xe3, (byte)0x13, (byte)0x3c, 
            (byte)0xef, (byte)0xf1, (byte)0xaa, (byte)0xcf, 
            (byte)0x2f, (byte)0x40, (byte)0x30, (byte)0x11
        });
        knownTest(algorithm, 1, 
            "abc", new byte[] { 
            (byte)0xb2, (byte)0x85, (byte)0x05, (byte)0x6d, 
            (byte)0xbf, (byte)0x18, (byte)0xd7, (byte)0x39, 
            (byte)0x2d, (byte)0x76, (byte)0x77, (byte)0x36, 
            (byte)0x95, (byte)0x24, (byte)0xdd, (byte)0x14, 
            (byte)0x74, (byte)0x74, (byte)0x59, (byte)0xed, 
            (byte)0x81, (byte)0x43, (byte)0x99, (byte)0x7e, 
            (byte)0x16, (byte)0x3b, (byte)0x29, (byte)0x86, 
            (byte)0xf9, (byte)0x2f, (byte)0xd4, (byte)0x2c        
        });
        knownTest(algorithm, 1, 
            "message digest", new byte[] { 
            (byte)0xbc, (byte)0x60, (byte)0x41, (byte)0xdd, 
            (byte)0x2a, (byte)0xa4, (byte)0x01, (byte)0xeb, 
            (byte)0xfa, (byte)0x6e, (byte)0x98, (byte)0x86, 
            (byte)0x73, (byte)0x41, (byte)0x74, (byte)0xfe, 
            (byte)0xbd, (byte)0xb4, (byte)0x72, (byte)0x9a, 
            (byte)0xa9, (byte)0x72, (byte)0xd6, (byte)0x0f, 
            (byte)0x54, (byte)0x9a, (byte)0xc3, (byte)0x9b, 
            (byte)0x29, (byte)0x72, (byte)0x1b, (byte)0xa0
        });
        knownTest(algorithm, 1, 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + 
            "abcdefghijklmnopqrstuvwxyz0123456789", new byte[] { 
            (byte)0x73, (byte)0xb7, (byte)0x0a, (byte)0x39, 
            (byte)0x49, (byte)0x7d, (byte)0xe5, (byte)0x3a, 
            (byte)0x6e, (byte)0x08, (byte)0xc6, (byte)0x7b, 
            (byte)0x6d, (byte)0x4d, (byte)0xb8, (byte)0x53, 
            (byte)0x54, (byte)0x0f, (byte)0x03, (byte)0xe9, 
            (byte)0x38, (byte)0x92, (byte)0x99, (byte)0xd9, 
            (byte)0xb0, (byte)0x15, (byte)0x6e, (byte)0xf7, 
            (byte)0xe8, (byte)0x5d, (byte)0x0f, (byte)0x61
        });
        knownTest(algorithm, 1, 
            "1234567890123456789012345678901234567890" + 
            "1234567890123456789012345678901234567890", new byte[] { 
            (byte)0x6b, (byte)0xc7, (byte)0xb3, (byte)0x89, 
            (byte)0x89, (byte)0xb2, (byte)0x8c, (byte)0xf9, 
            (byte)0x3a, (byte)0xe8, (byte)0x84, (byte)0x2b, 
            (byte)0xf9, (byte)0xd7, (byte)0x52, (byte)0x90, 
            (byte)0x59, (byte)0x10, (byte)0xa7, (byte)0x52, 
            (byte)0x8a, (byte)0x61, (byte)0xe5, (byte)0xbc, 
            (byte)0xe0, (byte)0x78, (byte)0x2d, (byte)0xe4, 
            (byte)0x3e, (byte)0x61, (byte)0x0c, (byte)0x90
        });
        knownTest(algorithm, 1, 
            "This is message, length=32 bytes", new byte[] { 
            (byte)0x2c, (byte)0xef, (byte)0xc2, (byte)0xf7, 
            (byte)0xb7, (byte)0xbd, (byte)0xc5, (byte)0x14, 
            (byte)0xe1, (byte)0x8e, (byte)0xa5, (byte)0x7f, 
            (byte)0xa7, (byte)0x4f, (byte)0xf3, (byte)0x57, 
            (byte)0xe7, (byte)0xfa, (byte)0x17, (byte)0xd6, 
            (byte)0x52, (byte)0xc7, (byte)0x5f, (byte)0x69, 
            (byte)0xcb, (byte)0x1b, (byte)0xe7, (byte)0x89, 
            (byte)0x3e, (byte)0xde, (byte)0x48, (byte)0xeb
        });
        knownTest(algorithm, 1, 
            "Suppose the original message has length = 50 bytes", new byte[] { 
            (byte)0xc3, (byte)0x73, (byte)0x0c, (byte)0x5c, 
            (byte)0xbc, (byte)0xca, (byte)0xcf, (byte)0x91, 
            (byte)0x5a, (byte)0xc2, (byte)0x92, (byte)0x67, 
            (byte)0x6f, (byte)0x21, (byte)0xe8, (byte)0xbd, 
            (byte)0x4e, (byte)0xf7, (byte)0x53, (byte)0x31, 
            (byte)0xd9, (byte)0x40, (byte)0x5e, (byte)0x5f, 
            (byte)0x1a, (byte)0x61, (byte)0xdc, (byte)0x31, 
            (byte)0x30, (byte)0xa6, (byte)0x50, (byte)0x11
        });
        knownTest(algorithm, 128, 
            "U", new byte[] { 
            (byte)0x1c, (byte)0x4a, (byte)0xc7, (byte)0x61, 
            (byte)0x46, (byte)0x91, (byte)0xbb, (byte)0xf4, 
            (byte)0x27, (byte)0xfa, (byte)0x23, (byte)0x16, 
            (byte)0x21, (byte)0x6b, (byte)0xe8, (byte)0xf1, 
            (byte)0x0d, (byte)0x92, (byte)0xed, (byte)0xfd, 
            (byte)0x37, (byte)0xcd, (byte)0x10, (byte)0x27, 
            (byte)0x51, (byte)0x4c, (byte)0x10, (byte)0x08, 
            (byte)0xf6, (byte)0x49, (byte)0xc4, (byte)0xe8
        });
/*        
        knownTest(algorithm, 1000000, 
            "a", new byte[] { 
            (byte)0x86, (byte)0x93, (byte)0x28, (byte)0x7a, 
            (byte)0xa6, (byte)0x2f, (byte)0x94, (byte)0x78, 
            (byte)0xf7, (byte)0xcb, (byte)0x31, (byte)0x2e, 
            (byte)0xc0, (byte)0x86, (byte)0x6b, (byte)0x6c, 
            (byte)0x4e, (byte)0x4a, (byte)0x0f, (byte)0x11, 
            (byte)0x16, (byte)0x04, (byte)0x41, (byte)0xe8, 
            (byte)0xf4, (byte)0xff, (byte)0xcd, (byte)0x27, 
            (byte)0x15, (byte)0xdd, (byte)0x55, (byte)0x4f
        });
*/
        knownTest(algorithm, 1, 
            "The quick brown fox jumps over the lazy dog", new byte[] { 
            (byte)0x90, (byte)0x04, (byte)0x29, (byte)0x4a, 
            (byte)0x36, (byte)0x1a, (byte)0x50, (byte)0x8c, 
            (byte)0x58, (byte)0x6f, (byte)0xe5, (byte)0x3d, 
            (byte)0x1f, (byte)0x1b, (byte)0x02, (byte)0x74, 
            (byte)0x67, (byte)0x65, (byte)0xe7, (byte)0x1b, 
            (byte)0x76, (byte)0x54, (byte)0x72, (byte)0x78,
            (byte)0x6e, (byte)0x47, (byte)0x70, (byte)0xd5, 
            (byte)0x65, (byte)0x83, (byte)0x0a, (byte)0x76
        });
    }
    ////////////////////////////////////////////////////////////////////////////
    // PBKDF2 HMAC ГОСТ Р 34.11-1994
    ////////////////////////////////////////////////////////////////////////////
    public static void testPBKDF2(
        Factory factory, SecurityStore scope) throws Exception
    {
        AlgorithmIdentifier prf = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_94_HMAC), Null.INSTANCE
        ); 
        PBKDF2.test(factory, scope, prf, "password", 
            "salt".getBytes("UTF-8"), 1, new byte[] {
            (byte)0x73, (byte)0x14, (byte)0xe7, (byte)0xc0, 
            (byte)0x4f, (byte)0xb2, (byte)0xe6, (byte)0x62, 
            (byte)0xc5, (byte)0x43, (byte)0x67, (byte)0x42, 
            (byte)0x53, (byte)0xf6, (byte)0x8b, (byte)0xd0, 
            (byte)0xb7, (byte)0x34, (byte)0x45, (byte)0xd0, 
            (byte)0x7f, (byte)0x24, (byte)0x1b, (byte)0xed, 
            (byte)0x87, (byte)0x28, (byte)0x82, (byte)0xda, 
            (byte)0x21, (byte)0x66, (byte)0x2d, (byte)0x58                
        }); 
        PBKDF2.test(factory, scope, prf, "password", 
            "salt".getBytes("UTF-8"), 2, new byte[] {
            (byte)0x99, (byte)0x0d, (byte)0xfa, (byte)0x2b, 
            (byte)0xd9, (byte)0x65, (byte)0x63, (byte)0x9b, 
            (byte)0xa4, (byte)0x8b, (byte)0x07, (byte)0xb7, 
            (byte)0x92, (byte)0x77, (byte)0x5d, (byte)0xf7, 
            (byte)0x9f, (byte)0x2d, (byte)0xb3, (byte)0x4f, 
            (byte)0xef, (byte)0x25, (byte)0xf2, (byte)0x74, 
            (byte)0x37, (byte)0x88, (byte)0x72, (byte)0xfe, 
            (byte)0xd7, (byte)0xed, (byte)0x1b, (byte)0xb3
        }); 
        PBKDF2.test(factory, scope, prf, "password", 
            "salt".getBytes("UTF-8"), 4096, new byte[] {
            (byte)0x1f, (byte)0x18, (byte)0x29, (byte)0xa9, 
            (byte)0x4b, (byte)0xdf, (byte)0xf5, (byte)0xbe, 
            (byte)0x10, (byte)0xd0, (byte)0xae, (byte)0xb3, 
            (byte)0x6a, (byte)0xf4, (byte)0x98, (byte)0xe7, 
            (byte)0xa9, (byte)0x74, (byte)0x67, (byte)0xf3, 
            (byte)0xb3, (byte)0x11, (byte)0x16, (byte)0xa5, 
            (byte)0xa7, (byte)0xc1, (byte)0xaf, (byte)0xff, 
            (byte)0x9d, (byte)0xea, (byte)0xda, (byte)0xfe
        }); 
/*      PBKDF2.test(factory, scope, prf, "password", 
            "salt".getBytes("UTF-8"), 16777216, new byte[] {
            (byte)0xa5, (byte)0x7a, (byte)0xe5, (byte)0xa6, 
            (byte)0x08, (byte)0x83, (byte)0x96, (byte)0xd1, 
            (byte)0x20, (byte)0x85, (byte)0x0c, (byte)0x5c, 
            (byte)0x09, (byte)0xde, (byte)0x0a, (byte)0x52, 
            (byte)0x51, (byte)0x00, (byte)0x93, (byte)0x8a, 
            (byte)0x59, (byte)0xb1, (byte)0xb5, (byte)0xc3, 
            (byte)0xf7, (byte)0x81, (byte)0x09, (byte)0x10, 
            (byte)0xd0, (byte)0x5f, (byte)0xcd, (byte)0x97        
        }); 
*/      PBKDF2.test(factory, scope, prf, "passwordPASSWORDpassword", 
            "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes("UTF-8"), 
            4096, new byte[] {
            (byte)0x78, (byte)0x83, (byte)0x58, (byte)0xc6, 
            (byte)0x9c, (byte)0xb2, (byte)0xdb, (byte)0xe2, 
            (byte)0x51, (byte)0xa7, (byte)0xbb, (byte)0x17, 
            (byte)0xd5, (byte)0xf4, (byte)0x24, (byte)0x1f, 
            (byte)0x26, (byte)0x5a, (byte)0x79, (byte)0x2a, 
            (byte)0x35, (byte)0xbe, (byte)0xcd, (byte)0xe8, 
            (byte)0xd5, (byte)0x6f, (byte)0x32, (byte)0x6b, 
            (byte)0x49, (byte)0xc8, (byte)0x50, (byte)0x47, 
            (byte)0xb7, (byte)0x63, (byte)0x8a, (byte)0xcb, 
            (byte)0x47, (byte)0x64, (byte)0xb1, (byte)0xfd        
        }); 
        PBKDF2.test(factory, scope, prf, "pass\0word", 
            "sa\0lt".getBytes("UTF-8"), 4096, new byte[] {
            (byte)0x43, (byte)0xe0, (byte)0x6c, (byte)0x55, 
            (byte)0x90, (byte)0xb0, (byte)0x8c, (byte)0x02, 
            (byte)0x25, (byte)0x24, (byte)0x23, (byte)0x73, 
            (byte)0x12, (byte)0x7e, (byte)0xdf, (byte)0x9c, 
            (byte)0x8e, (byte)0x9c, (byte)0x32, (byte)0x91        
        }); 
    }
}
