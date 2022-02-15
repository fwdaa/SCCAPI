package aladdin.capi.gost.hash;
import aladdin.math.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования ГОСТ Р 34.11-2012
///////////////////////////////////////////////////////////////////////////
public class GOSTR3411_2012 extends BlockHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
	///////////////////////////////////////////////////////////////////////////
	// Целочисленное сложение
	///////////////////////////////////////////////////////////////////////////
    private static void ADD(long[] a, long[] k, long[] result)
    {
        // для всех компонентов
        long carry = 0; for (int i = 0; i < a.length; i++) 
        {
            // выполнить сложение
            long b = carry + a[i]; result[i] = b + k[i]; carry = 0;

            // проверить наличие первого переноса
    		if (carry != 0 && b == 0) carry = 1; else if (b >= 0)
			{
				// проверить наличие второго переноса
				if (result[i] >= 0 && result[i] < b) carry = 1;
			}
			// проверить наличие второго переноса
			else if (result[i] >= 0 || result[i] < b) carry = 1;
        }
    }
    private static void ADD(long[] a, long k, long[] result)
    {
        // выполнить сложение
        long carry = 0; result[0] = a[0] + k; if (k >= 0)
		{
			// проверить наличие переноса
			if (result[0] >= 0 && result[0] < k) carry = 1;
		}
		// проверить наличие переноса
		else if (result[0] >= 0 || result[0] < k) carry = 1;

        // для всех компонентов
        for (int i = 1; carry != 0 && i < a.length; i++) 
        {
            // выполнить сложение
            result[i] = carry + a[i]; 

            // проверить наличие переноса
            carry = (carry != 0 && result[i] == 0) ? 1 : 0; 
        }
    }
	///////////////////////////////////////////////////////////////////////////
	// Преобразование X
	///////////////////////////////////////////////////////////////////////////
    private static void X(long[] a, long[] k, long[] result)
    {
        // выполнить преобразование X
        for (int i = 0; i < a.length; i++) result[i] = a[i] ^ k[i]; 
    }
	///////////////////////////////////////////////////////////////////////////
	// Преобразование S
	///////////////////////////////////////////////////////////////////////////
    private static final byte[] Pi = new byte[] { 
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
    private static void S(long[] a, byte[] result)
    {
        // для всех 64-разрядных слов
        for (int i = 0; i < a.length; i++)
        {
            // для всех байтов слов
            for (int j = 0; j < 8; j++) 
            {
                // извлечь значение байта
                byte bt = (byte)((a[i] >>> (j * 8)) & 0xFF);

                // выполнить подстановку
                result[i * 8 + j] = Pi[bt & 0xFF]; 
            }
        }
    }
	///////////////////////////////////////////////////////////////////////////
	// преобразование P
	///////////////////////////////////////////////////////////////////////////
    private static void P(byte[] a, long[] result)
    {
        // обнулить результат
        for (int i = 0; i < a.length / 8; i++) result[i] = 0; 

        // для всех 64-разрядных слов
        for (int i = 0; i < 8; i++)
        {
            // для всех байтов слов
            for (int j = 0; j < 8; j++)
            {
                // выполнить перестановку
                result[i] |= (long)(a[i + j * 8] & 0xFF) << (j * 8); 
            }
        }
    }
	///////////////////////////////////////////////////////////////////////////
	// Преобразование l
	///////////////////////////////////////////////////////////////////////////
    private static final long[] A = {
        0x8e20faa72ba0b470L, 0x47107ddd9b505a38L, 
	    0xad08b0e0c3282d1cL, 0xd8045870ef14980eL,
        0x6c022c38f90a4c07L, 0x3601161cf205268dL, 
		0x1b8e0b0e798c13c8L, 0x83478b07b2468764L,
        0xa011d380818e8f40L, 0x5086e740ce47c920L, 
		0x2843fd2067adea10L, 0x14aff010bdd87508L,
        0x0ad97808d06cb404L, 0x05e23c0468365a02L, 
		0x8c711e02341b2d01L, 0x46b60f011a83988eL,
        0x90dab52a387ae76fL, 0x486dd4151c3dfdb9L, 
		0x24b86a840e90f0d2L, 0x125c354207487869L,
        0x092e94218d243cbaL, 0x8a174a9ec8121e5dL, 
		0x4585254f64090fa0L, 0xaccc9ca9328a8950L,
        0x9d4df05d5f661451L, 0xc0a878a0a1330aa6L, 
		0x60543c50de970553L, 0x302a1e286fc58ca7L,
        0x18150f14b9ec46ddL, 0x0c84890ad27623e0L, 
		0x0642ca05693b9f70L, 0x0321658cba93c138L,
        0x86275df09ce8aaa8L, 0x439da0784e745554L, 
		0xafc0503c273aa42aL, 0xd960281e9d1d5215L,
        0xe230140fc0802984L, 0x71180a8960409a42L, 
		0xb60c05ca30204d21L, 0x5b068c651810a89eL,
        0x456c34887a3805b9L, 0xac361a443d1c8cd2L, 
		0x561b0d22900e4669L, 0x2b838811480723baL,
        0x9bcf4486248d9f5dL, 0xc3e9224312c8c1a0L, 
		0xeffa11af0964ee50L, 0xf97d86d98a327728L,
        0xe4fa2054a80b329cL, 0x727d102a548b194eL, 
		0x39b008152acb8227L, 0x9258048415eb419dL,
        0x492c024284fbaec0L, 0xaa16012142f35760L, 
		0x550b8e9e21f7a530L, 0xa48b474f9ef5dc18L,
        0x70a6a56e2440598eL, 0x3853dc371220a247L, 
		0x1ca76e95091051adL, 0x0edd37c48a08a6d8L,
        0x07e095624504536cL, 0x8d70c431ac02a736L, 
		0xc83862965601dd1bL, 0x641c314b2b8ee083L
    }; 
    private static void L(long[] a)
    {
        // для всех 64-разрядных компонентов
        for (int i = 0; i < a.length; i++)
        {
            // для всех битов компонента
            long sum = 0; for (int j = 0; j < 64; j++)
            {
                // выполнить линейное преобразование
                if ((a[i] & ((long)1 << j)) != 0) sum ^= A[63 - j];
            }
            a[i] = sum; 
        }
    } 
	///////////////////////////////////////////////////////////////////////////
	// преобразование LPS
	///////////////////////////////////////////////////////////////////////////
    private static void LPS(long[] a)
    {
        // выполнить преобразования
        byte[] b = new byte[a.length * 8]; S(a, b); P(b, a); L(a);
    }
	///////////////////////////////////////////////////////////////////////////
	// Итерационные константы
	///////////////////////////////////////////////////////////////////////////
    private static final long[][] C = { 
        new long []{   
            0xdd806559f2a64507L, 0x05767436cc744d23L, 
			0xa2422a08a460d315L, 0x4b7ce09192676901L, 
            0x714eb88d7585c4fcL, 0x2f6a76432e45d016L, 
			0xebcb2f81c0657c1fL, 0xb1085bda1ecadae9L
        }, new long [] {
            0xe679047021b19bb7L, 0x55dda21bd7cbcd56L, 
			0x5cb561c2db0aa7caL, 0x9ab5176b12d69958L,
            0x61d55e0f16b50131L, 0xf3feea720a232b98L, 
			0x4fe39d460f70b5d7L, 0x6fa3b58aa99d2f1aL,
        }, new long [] {
            0x991e96f50aba0ab2L, 0xc2b6f443867adb31L, 
			0xc1c93a376062db09L, 0xd3e20fe490359eb1L,
            0xf2ea7514b1297b7bL, 0x06f15e5f529c1f8bL, 
			0x0a39fc286a3d8435L, 0xf574dcac2bce2fc7L,
        }, new long [] {
            0x220cbebc84e3d12eL, 0x3453eaa193e837f1L, 
			0xd8b71333935203beL, 0xa9d72c82ed03d675L,
            0x9d721cad685e353fL, 0x488e857e335c3c7dL, 
			0xf948e1a05d71e4ddL, 0xef1fdfb3e81566d2L
        }, new long [] {
            0x601758fd7c6cfe57L, 0x7a56a27ea9ea63f5L, 
            0xdfff00b723271a16L, 0xbfcd1747253af5a3L, 
            0x359e35d7800fffbdL, 0x7f151c1f1686104aL, 
			0x9a3f410c6ca92363L, 0x4bea6bacad474799L,
        }, new long [] {
            0xfa68407a46647d6eL, 0xbf71c57236904f35L, 
			0x0af21f66c2bec6b6L, 0xcffaa6b71c9ab7b4L,
            0x187f9ab49af08ec6L, 0x2d66c4f95142a46cL, 
			0x6fa4c33b7a3039c0L, 0xae4faeae1d3ad3d9L,
        }, new long [] {
            0x8886564d3a14d493L, 0x3517454ca23c4af3L, 
            0x06476983284a0504L, 0x0992abc52d822c37L,
            0xd3473e33197a93c9L, 0x399ec6c7e6bf87c9L, 
			0x51ac86febf240954L, 0xf4c70e16eeaac5ecL,
        }, new long [] {
            0xa47f0dd4bf02e71eL, 0x36acc2355951a8d9L, 
            0x69d18d2bd1a5c42fL, 0xf4892bcb929b0690L,
            0x89b4443b4ddbc49aL, 0x4eb7f8719c36de1eL, 
			0x03e7aa020c6e4141L, 0x9b1f5b424d93c9a7L,
        }, new long [] {
            0x7261445183235adbL, 0x0e38dc92cb1f2a60L, 
            0x7b2b8a9aa6079c54L, 0x800a440bdbb2ceb1L, 
            0x3cd955b7e00d0984L, 0x3a7d3a1b25894224L, 
			0x944c9ad8ec165fdeL, 0x378f5a541631229bL,
        }, new long [] {
            0x74b4c7fb98459cedL, 0x3698fad1153bb6c3L, 
			0x7a1e6c303b7652f4L, 0x9fe76702af69334bL,
            0x1fffe18a1b336103L, 0x8941e71cff8a78dbL, 
			0x382ae548b2e4f3f3L, 0xabbedea680056f52L,
        }, new long [] {
            0x6bcaa4cd81f32d1bL, 0xdea2594ac06fd85dL, 
			0xefbacd1d7d476e98L, 0x8a1d71efea48b9caL,
            0x2001802114846679L, 0xd8fa6bbbebab0761L, 
			0x3002c6cd635afe94L, 0x7bcd9ed0efc889fbL,
        }, new long [] {
            0x48bc924af11bd720L, 0xfaf417d5d9b21b99L, 
			0xe71da4aa88e12852L, 0x5d80ef9d1891cc86L,
            0xf82012d430219f9bL, 0xcda43c32bcdf1d77L, 
			0xd21380b00449b17aL, 0x378ee767f11631baL, 
        }
    }; 
	///////////////////////////////////////////////////////////////////////////
	// Преобразование E (результат в K)
	///////////////////////////////////////////////////////////////////////////
    private static void E(long[] K, long[] m)
    {
        // выделить вспомогательный буфер
        long[] result = new long[m.length]; 

        // установить начальные условия
        System.arraycopy(m, 0, result, 0, m.length); 

        // для каждой итерации
        for (int i = 0; i < 12; i++)
        {
            // выполнить преобразование
            X(result, K, result); LPS(result); 

            // выполнить преобразование
            X(K, C[i], K); LPS(K);
        }
        // выполнить преобразование
        X(K, result, K);
    }
	///////////////////////////////////////////////////////////////////////////
	// Функция сжатия
	///////////////////////////////////////////////////////////////////////////
    private static void G(long[] h, long[] m, long[] N)
    {
        // выделить вспомогательный буфер
        long[] result = new long[h.length]; 

        // выполнить преобразование
        X(h, N, result); LPS(result); E(result, m); 

        // выполнить преобразование
        X(result, m, result); X(result, h, h); 
    }
	///////////////////////////////////////////////////////////////////////////
	// Конструктор
	///////////////////////////////////////////////////////////////////////////
	private final long[] hash;	// текущее хэш-значение
	private final long[] N;	    // вспомогательный буфер
	private final long[] sum;	// аккумулятор
    private final int	 size;	// размер хэш-значения

    public GOSTR3411_2012(int bits) 
	{ 
        // сохранить переданные параметры
		super(); this.size = bits / 8; hash = new long[8];

        // выделить память для текущего хэш-значения
        N = new long[8]; sum = new long[8]; 
	}
	// размер блока алгоритма хэширования
	@Override public final int blockSize() { return 64; }

	// размер хэш-значения в байтах
	@Override public final int hashSize() { return size; }

	///////////////////////////////////////////////////////////////////////////
	// Вычислить хэш-значение
	///////////////////////////////////////////////////////////////////////////
	@Override public void init() throws IOException
	{
		// обнулить стартовое хэш-значение
		super.init(); for (int i = 0; i < hash.length; i++) hash[i] = 0; 
        
        // установить стартовое хэш-значение
        if (size == 32) for (int i = 0; i < hash.length; i++) 
    	{
			// установить фиксированное значение
			hash[i] = 0x0101010101010101L; 
		}
        // обнулить аккумулятор
		for (int i = 0; i < N  .length; i++) N  [i] = 0; 
        for (int i = 0; i < sum.length; i++) sum[i] = 0;
	}
	@Override protected void update(byte[] data, int dataOff)
	{
        // выделить вспомогательный буфер
        long[] m = new long[hash.length]; 

        // для всех байтов
        for (int i = 0; i < m.length; i++)
        {
            m[i] = Convert.toInt64(data, dataOff + 8 * i, ENDIAN); 
        }
        // выполнить тактовую функцию
        G(hash, m, N); ADD(N, 512, N); ADD(sum, m, sum); 
    }
	@Override protected void finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	{
        // обработать последний полный блок
        if (dataLen == 64) { update(data, dataOff);

            // пропустить обработанный блок
            dataOff += 64; dataLen -= 64; 
        }
        // выделить вспомогательный буфер
        long[] m = new long[hash.length]; 

        // для всех байтов
        for (int i = 0; i < dataLen; i++)
        {
            // выполнить преобразование данных
            m[i / 8] |= (long)(data[dataOff + i] & 0xFF) << ((i % 8) * 8); 
        }
        // выполнить дополнение данных
        m[dataLen / 8] |= (long)1 << ((dataLen % 8) * 8);

        // выполнить тактовую функцию
        G(hash, m, N); ADD(N, (long)dataLen * 8, N); ADD(sum, m, sum); 

        // выполнить сжатие данных
        G(hash, N, new long[8]); G(hash, sum, new long[8]); 

        // определить смещение результата
        int offset = hash.length - size / 8; 

        // для всех 64-разрядных компонентов
        for (int i = 0; i < size / 8; i++)
        {
            // скопировть 64-разрядный компонент
            Convert.fromInt64(hash[offset + i], ENDIAN, buf, bufOff + i * 8);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test256(Hash algorithm) throws Exception
    {
        knownTest(algorithm, 1, new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, 
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x30, (byte)0x31, 
            (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, 
            (byte)0x36, (byte)0x37, (byte)0x38, (byte)0x39, 
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, 
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x30, (byte)0x31, 
            (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, 
            (byte)0x36, (byte)0x37, (byte)0x38, (byte)0x39, 
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, 
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x30, (byte)0x31, 
            (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, 
            (byte)0x36, (byte)0x37, (byte)0x38, (byte)0x39, 
            (byte)0x30, (byte)0x31, (byte)0x32
        }, new byte[] { 
            (byte)0x9d, (byte)0x15, (byte)0x1e, (byte)0xef,
            (byte)0xd8, (byte)0x59, (byte)0x0b, (byte)0x89,
            (byte)0xda, (byte)0xa6, (byte)0xba, (byte)0x6c,
            (byte)0xb7, (byte)0x4a, (byte)0xf9, (byte)0x27,
            (byte)0x5d, (byte)0xd0, (byte)0x51, (byte)0x02,
            (byte)0x6b, (byte)0xb1, (byte)0x49, (byte)0xa4,
            (byte)0x52, (byte)0xfd, (byte)0x84, (byte)0xe5,
            (byte)0xe5, (byte)0x7b, (byte)0x55, (byte)0x00
        });
        knownTest(algorithm, 1, new byte[] {
            (byte)0xd1, (byte)0xe5, (byte)0x20, (byte)0xe2,
            (byte)0xe5, (byte)0xf2, (byte)0xf0, (byte)0xe8,
            (byte)0x2c, (byte)0x20, (byte)0xd1, (byte)0xf2,
            (byte)0xf0, (byte)0xe8, (byte)0xe1, (byte)0xee,
            (byte)0xe6, (byte)0xe8, (byte)0x20, (byte)0xe2,
            (byte)0xed, (byte)0xf3, (byte)0xf6, (byte)0xe8,
            (byte)0x2c, (byte)0x20, (byte)0xe2, (byte)0xe5,
            (byte)0xfe, (byte)0xf2, (byte)0xfa, (byte)0x20,
            (byte)0xf1, (byte)0x20, (byte)0xec, (byte)0xee,
            (byte)0xf0, (byte)0xff, (byte)0x20, (byte)0xf1,
            (byte)0xf2, (byte)0xf0, (byte)0xe5, (byte)0xeb,
            (byte)0xe0, (byte)0xec, (byte)0xe8, (byte)0x20,
            (byte)0xed, (byte)0xe0, (byte)0x20, (byte)0xf5,
            (byte)0xf0, (byte)0xe0, (byte)0xe1, (byte)0xf0,
            (byte)0xfb, (byte)0xff, (byte)0x20, (byte)0xef,
            (byte)0xeb, (byte)0xfa, (byte)0xea, (byte)0xfb,
            (byte)0x20, (byte)0xc8, (byte)0xe3, (byte)0xee,
            (byte)0xf0, (byte)0xe5, (byte)0xe2, (byte)0xfb           
        }, new byte[] { 
            (byte)0x9d, (byte)0xd2, (byte)0xfe, (byte)0x4e,
            (byte)0x90, (byte)0x40, (byte)0x9e, (byte)0x5d,
            (byte)0xa8, (byte)0x7f, (byte)0x53, (byte)0x97, 
            (byte)0x6d, (byte)0x74, (byte)0x05, (byte)0xb0,
            (byte)0xc0, (byte)0xca, (byte)0xc6, (byte)0x28,
            (byte)0xfc, (byte)0x66, (byte)0x9a, (byte)0x74,
            (byte)0x1d, (byte)0x50, (byte)0x06, (byte)0x3c,
            (byte)0x55, (byte)0x7e, (byte)0x8f, (byte)0x50
        });
    }
    public static void test512(Hash algorithm) throws Exception
    {
        knownTest(algorithm, 1, new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, 
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x30, (byte)0x31, 
            (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, 
            (byte)0x36, (byte)0x37, (byte)0x38, (byte)0x39, 
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, 
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x30, (byte)0x31, 
            (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, 
            (byte)0x36, (byte)0x37, (byte)0x38, (byte)0x39, 
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, 
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x30, (byte)0x31, 
            (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, 
            (byte)0x36, (byte)0x37, (byte)0x38, (byte)0x39, 
            (byte)0x30, (byte)0x31, (byte)0x32
        }, new byte[] { 
            (byte)0x1b, (byte)0x54, (byte)0xd0, (byte)0x1a,
            (byte)0x4a, (byte)0xf5, (byte)0xb9, (byte)0xd5, 
            (byte)0xcc, (byte)0x3d, (byte)0x86, (byte)0xd6, 
            (byte)0x8d, (byte)0x28, (byte)0x54, (byte)0x62,
            (byte)0xb1, (byte)0x9a, (byte)0xbc, (byte)0x24, 
            (byte)0x75, (byte)0x22, (byte)0x2f, (byte)0x35,
            (byte)0xc0, (byte)0x85, (byte)0x12, (byte)0x2b,
            (byte)0xe4, (byte)0xba, (byte)0x1f, (byte)0xfa,
            (byte)0x00, (byte)0xad, (byte)0x30, (byte)0xf8,
            (byte)0x76, (byte)0x7b, (byte)0x3a, (byte)0x82,
            (byte)0x38, (byte)0x4c, (byte)0x65, (byte)0x74,
            (byte)0xf0, (byte)0x24, (byte)0xc3, (byte)0x11,
            (byte)0xe2, (byte)0xa4, (byte)0x81, (byte)0x33,
            (byte)0x2b, (byte)0x08, (byte)0xef, (byte)0x7f,
            (byte)0x41, (byte)0x79, (byte)0x78, (byte)0x91,
            (byte)0xc1, (byte)0x64, (byte)0x6f, (byte)0x48
        });
        knownTest(algorithm, 1, new byte[] {
            (byte)0xd1, (byte)0xe5, (byte)0x20, (byte)0xe2,
            (byte)0xe5, (byte)0xf2, (byte)0xf0, (byte)0xe8,
            (byte)0x2c, (byte)0x20, (byte)0xd1, (byte)0xf2,
            (byte)0xf0, (byte)0xe8, (byte)0xe1, (byte)0xee,
            (byte)0xe6, (byte)0xe8, (byte)0x20, (byte)0xe2,
            (byte)0xed, (byte)0xf3, (byte)0xf6, (byte)0xe8,
            (byte)0x2c, (byte)0x20, (byte)0xe2, (byte)0xe5,
            (byte)0xfe, (byte)0xf2, (byte)0xfa, (byte)0x20,
            (byte)0xf1, (byte)0x20, (byte)0xec, (byte)0xee,
            (byte)0xf0, (byte)0xff, (byte)0x20, (byte)0xf1,
            (byte)0xf2, (byte)0xf0, (byte)0xe5, (byte)0xeb,
            (byte)0xe0, (byte)0xec, (byte)0xe8, (byte)0x20,
            (byte)0xed, (byte)0xe0, (byte)0x20, (byte)0xf5,
            (byte)0xf0, (byte)0xe0, (byte)0xe1, (byte)0xf0,
            (byte)0xfb, (byte)0xff, (byte)0x20, (byte)0xef,
            (byte)0xeb, (byte)0xfa, (byte)0xea, (byte)0xfb,
            (byte)0x20, (byte)0xc8, (byte)0xe3, (byte)0xee,
            (byte)0xf0, (byte)0xe5, (byte)0xe2, (byte)0xfb           
        }, new byte[] { 
            (byte)0x1e, (byte)0x88, (byte)0xe6, (byte)0x22,
            (byte)0x26, (byte)0xbf, (byte)0xca, (byte)0x6f,
            (byte)0x99, (byte)0x94, (byte)0xf1, (byte)0xf2,
            (byte)0xd5, (byte)0x15, (byte)0x69, (byte)0xe0,
            (byte)0xda, (byte)0xf8, (byte)0x47, (byte)0x5a,
            (byte)0x3b, (byte)0x0f, (byte)0xe6, (byte)0x1a,
            (byte)0x53, (byte)0x00, (byte)0xee, (byte)0xe4,
            (byte)0x6d, (byte)0x96, (byte)0x13, (byte)0x76,
            (byte)0x03, (byte)0x5f, (byte)0xe8, (byte)0x35,
            (byte)0x49, (byte)0xad, (byte)0xa2, (byte)0xb8,
            (byte)0x62, (byte)0x0f, (byte)0xcd, (byte)0x7c,
            (byte)0x49, (byte)0x6c, (byte)0xe5, (byte)0xb3,
            (byte)0x3f, (byte)0x0c, (byte)0xb9, (byte)0xdd,
            (byte)0xdc, (byte)0x2b, (byte)0x64, (byte)0x60,
            (byte)0x14, (byte)0x3b, (byte)0x03, (byte)0xda,
            (byte)0xba, (byte)0xc9, (byte)0xfb, (byte)0x28
        });
    }
    ////////////////////////////////////////////////////////////////////////////
    // HMAC
    ////////////////////////////////////////////////////////////////////////////
    public static void testHMAC256(Mac macAlgorithm) throws Exception
    {
        // выполнить тест
        if (KeySizes.contains(macAlgorithm.keySizes(), 32))
        Mac.knownTest(macAlgorithm, new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, 
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, 
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
            (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, 
            (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f
        }, 1, new byte[] {
            (byte)0x01, (byte)0x26, (byte)0xbd, (byte)0xb8, 
            (byte)0x78, (byte)0x00, (byte)0xaf, (byte)0x21, 
            (byte)0x43, (byte)0x41, (byte)0x45, (byte)0x65, 
            (byte)0x63, (byte)0x78, (byte)0x01, (byte)0x00
        }, new byte[] {
            (byte)0xa1, (byte)0xaa, (byte)0x5f, (byte)0x7d, 
            (byte)0xe4, (byte)0x02, (byte)0xd7, (byte)0xb3, 
            (byte)0xd3, (byte)0x23, (byte)0xf2, (byte)0x99, 
            (byte)0x1c, (byte)0x8d, (byte)0x45, (byte)0x34,
            (byte)0x01, (byte)0x31, (byte)0x37, (byte)0x01, 
            (byte)0x0a, (byte)0x83, (byte)0x75, (byte)0x4f, 
            (byte)0xd0, (byte)0xaf, (byte)0x6d, (byte)0x7c, 
            (byte)0xd4, (byte)0x92, (byte)0x2e, (byte)0xd9 
        });
    }
    public static void testHMAC512(Mac macAlgorithm) throws Exception
    {
        // выполнить тест
        if (KeySizes.contains(macAlgorithm.keySizes(), 32))
        Mac.knownTest(macAlgorithm, new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, 
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, 
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
            (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, 
            (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f
        }, 1, new byte[] {
            (byte)0x01, (byte)0x26, (byte)0xbd, (byte)0xb8, 
            (byte)0x78, (byte)0x00, (byte)0xaf, (byte)0x21, 
            (byte)0x43, (byte)0x41, (byte)0x45, (byte)0x65, 
            (byte)0x63, (byte)0x78, (byte)0x01, (byte)0x00
        }, new byte[] {
            (byte)0xa5, (byte)0x9b, (byte)0xab, (byte)0x22, 
            (byte)0xec, (byte)0xae, (byte)0x19, (byte)0xc6, 
            (byte)0x5f, (byte)0xbd, (byte)0xe6, (byte)0xe5, 
            (byte)0xf4, (byte)0xe9, (byte)0xf5, (byte)0xd8, 
            (byte)0x54, (byte)0x9d, (byte)0x31, (byte)0xf0, 
            (byte)0x37, (byte)0xf9, (byte)0xdf, (byte)0x9b, 
            (byte)0x90, (byte)0x55, (byte)0x00, (byte)0xe1, 
            (byte)0x71, (byte)0x92, (byte)0x3a, (byte)0x77, 
            (byte)0x3d, (byte)0x5f, (byte)0x15, (byte)0x30,
            (byte)0xf2, (byte)0xed, (byte)0x7e, (byte)0x96, 
            (byte)0x4c, (byte)0xb2, (byte)0xee, (byte)0xdc, 
            (byte)0x29, (byte)0xe9, (byte)0xad, (byte)0x2f, 
            (byte)0x3a, (byte)0xfe, (byte)0x93, (byte)0xb2, 
            (byte)0x81, (byte)0x4f, (byte)0x79, (byte)0xf5, 
            (byte)0x00, (byte)0x0f, (byte)0xfc, (byte)0x03, 
            (byte)0x66, (byte)0xc2, (byte)0x51, (byte)0xe6
        });
    }    
}
