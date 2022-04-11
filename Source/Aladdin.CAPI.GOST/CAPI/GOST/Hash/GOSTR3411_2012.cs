using System;

///////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования ГОСТ Р 34.11-2012
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.Hash
{
    public class GOSTR3411_2012 : BlockHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

		///////////////////////////////////////////////////////////////////////////
		// Целочисленное сложение
		///////////////////////////////////////////////////////////////////////////
        private static void ADD(ulong[] a, ulong[] k, ulong[] result)
        {
            // для всех компонентов
            ulong carry = 0; for (int i = 0; i < a.Length; i++) 
            {
                // выполнить сложение
                ulong b = unchecked(carry + a[i]); result[i] = unchecked(b + k[i]);

                // проверить наличие переноса
                carry = (ulong)((b < carry || result[i] < b) ? 1 : 0); 
            }
        }
        private static void ADD(ulong[] a, ulong k, ulong[] result)
        {
            // выполнить сложение
            result[0] = unchecked(a[0] + k); 

            // проверить наличие переноса
            ulong carry = (ulong)((result[0] < a[0]) ? 1 : 0); 

            // для всех компонентов
            for (int i = 1; carry > 0 && i < a.Length; i++) 
            {
                // выполнить сложение
                result[i] = unchecked(carry + a[i]); 

                // проверить наличие переноса
                carry = (ulong)((result[i] < carry) ? 1 : 0); 
            }
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Преобразование X
	    ///////////////////////////////////////////////////////////////////////////
        private static void X(ulong[] a, ulong[] k, ulong[] result)
        {
            // выполнить преобразование X
            for (int i = 0; i < a.Length; i++) result[i] = a[i] ^ k[i]; 
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Преобразование S
	    ///////////////////////////////////////////////////////////////////////////
        private static readonly byte[] Pi = new byte[] { 
            252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77, 
            233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193, 
            249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66, 139,   1, 142,  79, 
              5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31, 
            235,  52,  44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204, 
            181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156, 183,  93, 135, 
             21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 
             50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87, 
            223, 245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3, 
            224,  15, 236, 222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74, 
            167, 151,  96, 115,  30,   0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65, 
            173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165, 125, 105, 213, 149,  59, 
              7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228, 136, 217, 231, 137, 
            225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,  97,
             32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82, 
             89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,  75,  99, 182
        }; 
        private static void S(ulong[] a, byte[] result)
        {
            // для всех 64-разрядных слов
            for (int i = 0; i < a.Length; i++)
            {
                // для всех байтов слов
                for (int j = 0; j < 8; j++) 
                {
                    // извлечь значение байта
                    byte bt = (byte)((a[i] >> (j * 8)) & 0xFF);

                    // выполнить подстановку
                    result[i * 8 + j] = Pi[bt & 0xFF]; 
                }
            }
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Преобразовние P
	    ///////////////////////////////////////////////////////////////////////////
        private static void P(byte[] a, ulong[] result)
        {
            // обнулить результат
            for (int i = 0; i < a.Length / 8; i++) result[i] = 0; 

            // для всех 64-разрядных слов
            for (int i = 0; i < 8; i++)
            {
                // для всех байтов слов
                for (int j = 0; j < 8; j++)
                {
                    // выполнить перестановку
                    result[i] |= (ulong)(a[i + j * 8] & 0xFF) << (j * 8); 
                }
            }
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Преобразование l
	    ///////////////////////////////////////////////////////////////////////////
        private static readonly ulong[] A = {
            0x8e20faa72ba0b470L, 0x47107ddd9b505a38L, 0xad08b0e0c3282d1cL, 0xd8045870ef14980eL,
            0x6c022c38f90a4c07L, 0x3601161cf205268dL, 0x1b8e0b0e798c13c8L, 0x83478b07b2468764L,
            0xa011d380818e8f40L, 0x5086e740ce47c920L, 0x2843fd2067adea10L, 0x14aff010bdd87508L,
            0x0ad97808d06cb404L, 0x05e23c0468365a02L, 0x8c711e02341b2d01L, 0x46b60f011a83988eL,
            0x90dab52a387ae76fL, 0x486dd4151c3dfdb9L, 0x24b86a840e90f0d2L, 0x125c354207487869L,
            0x092e94218d243cbaL, 0x8a174a9ec8121e5dL, 0x4585254f64090fa0L, 0xaccc9ca9328a8950L,
            0x9d4df05d5f661451L, 0xc0a878a0a1330aa6L, 0x60543c50de970553L, 0x302a1e286fc58ca7L,
            0x18150f14b9ec46ddL, 0x0c84890ad27623e0L, 0x0642ca05693b9f70L, 0x0321658cba93c138L,
            0x86275df09ce8aaa8L, 0x439da0784e745554L, 0xafc0503c273aa42aL, 0xd960281e9d1d5215L,
            0xe230140fc0802984L, 0x71180a8960409a42L, 0xb60c05ca30204d21L, 0x5b068c651810a89eL,
            0x456c34887a3805b9L, 0xac361a443d1c8cd2L, 0x561b0d22900e4669L, 0x2b838811480723baL,
            0x9bcf4486248d9f5dL, 0xc3e9224312c8c1a0L, 0xeffa11af0964ee50L, 0xf97d86d98a327728L,
            0xe4fa2054a80b329cL, 0x727d102a548b194eL, 0x39b008152acb8227L, 0x9258048415eb419dL,
            0x492c024284fbaec0L, 0xaa16012142f35760L, 0x550b8e9e21f7a530L, 0xa48b474f9ef5dc18L,
            0x70a6a56e2440598eL, 0x3853dc371220a247L, 0x1ca76e95091051adL, 0x0edd37c48a08a6d8L,
            0x07e095624504536cL, 0x8d70c431ac02a736L, 0xc83862965601dd1bL, 0x641c314b2b8ee083L
        }; 
        private static void L(ulong[] a)
        {
            // для всех 64-разрядных компонентов
            for (int i = 0; i < a.Length; i++)
            {
                // для всех битов компонента
                ulong sum = 0; for (int j = 0; j < 64; j++)
                {
                    // выполнить линейное преобразование
                    if ((a[i] & ((ulong)1 << j)) != 0) sum ^= A[63 - j];
                }
                a[i] = sum; 
            }
        } 
	    ///////////////////////////////////////////////////////////////////////////
	    // Преобразовние LPS
	    ///////////////////////////////////////////////////////////////////////////
        private static void LPS(ulong[] a)
        {
            // выполнить преобразования
            byte[] b = new byte[a.Length * 8]; S(a, b); P(b, a); L(a);
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Итерационные константы
	    ///////////////////////////////////////////////////////////////////////////
        private static readonly ulong[][] C = { 
            new ulong []{   
                0xdd806559f2a64507L, 0x05767436cc744d23L, 0xa2422a08a460d315L, 0x4b7ce09192676901L, 
                0x714eb88d7585c4fcL, 0x2f6a76432e45d016L, 0xebcb2f81c0657c1fL, 0xb1085bda1ecadae9L
            }, new ulong [] {
                0xe679047021b19bb7L, 0x55dda21bd7cbcd56L, 0x5cb561c2db0aa7caL, 0x9ab5176b12d69958L,
                0x61d55e0f16b50131L, 0xf3feea720a232b98L, 0x4fe39d460f70b5d7L, 0x6fa3b58aa99d2f1aL,
            }, new ulong [] {
                0x991e96f50aba0ab2L, 0xc2b6f443867adb31L, 0xc1c93a376062db09L, 0xd3e20fe490359eb1L,
                0xf2ea7514b1297b7bL, 0x06f15e5f529c1f8bL, 0x0a39fc286a3d8435L, 0xf574dcac2bce2fc7L,
            }, new ulong [] {
                0x220cbebc84e3d12eL, 0x3453eaa193e837f1L, 0xd8b71333935203beL, 0xa9d72c82ed03d675L,
                0x9d721cad685e353fL, 0x488e857e335c3c7dL, 0xf948e1a05d71e4ddL, 0xef1fdfb3e81566d2L
            }, new ulong [] {
                0x601758fd7c6cfe57L, 0x7a56a27ea9ea63f5L, 0xdfff00b723271a16L, 0xbfcd1747253af5a3L, 
                0x359e35d7800fffbdL, 0x7f151c1f1686104aL, 0x9a3f410c6ca92363L, 0x4bea6bacad474799L,
            }, new ulong [] {
                0xfa68407a46647d6eL, 0xbf71c57236904f35L, 0x0af21f66c2bec6b6L, 0xcffaa6b71c9ab7b4L,
                0x187f9ab49af08ec6L, 0x2d66c4f95142a46cL, 0x6fa4c33b7a3039c0L, 0xae4faeae1d3ad3d9L,
            }, new ulong [] {
                0x8886564d3a14d493L, 0x3517454ca23c4af3L, 0x06476983284a0504L, 0x0992abc52d822c37L,
                0xd3473e33197a93c9L, 0x399ec6c7e6bf87c9L, 0x51ac86febf240954L, 0xf4c70e16eeaac5ecL,
            }, new ulong [] {
                0xa47f0dd4bf02e71eL, 0x36acc2355951a8d9L, 0x69d18d2bd1a5c42fL, 0xf4892bcb929b0690L,
                0x89b4443b4ddbc49aL, 0x4eb7f8719c36de1eL, 0x03e7aa020c6e4141L, 0x9b1f5b424d93c9a7L,
            }, new ulong [] {
                0x7261445183235adbL, 0x0e38dc92cb1f2a60L, 0x7b2b8a9aa6079c54L, 0x800a440bdbb2ceb1L, 
                0x3cd955b7e00d0984L, 0x3a7d3a1b25894224L, 0x944c9ad8ec165fdeL, 0x378f5a541631229bL,
            }, new ulong [] {
                0x74b4c7fb98459cedL, 0x3698fad1153bb6c3L, 0x7a1e6c303b7652f4L, 0x9fe76702af69334bL,
                0x1fffe18a1b336103L, 0x8941e71cff8a78dbL, 0x382ae548b2e4f3f3L, 0xabbedea680056f52L,
            }, new ulong [] {
                0x6bcaa4cd81f32d1bL, 0xdea2594ac06fd85dL, 0xefbacd1d7d476e98L, 0x8a1d71efea48b9caL,
                0x2001802114846679L, 0xd8fa6bbbebab0761L, 0x3002c6cd635afe94L, 0x7bcd9ed0efc889fbL,
            }, new ulong [] {
                0x48bc924af11bd720L, 0xfaf417d5d9b21b99L, 0xe71da4aa88e12852L, 0x5d80ef9d1891cc86L,
                0xf82012d430219f9bL, 0xcda43c32bcdf1d77L, 0xd21380b00449b17aL, 0x378ee767f11631baL, 
            }
        }; 
	    ///////////////////////////////////////////////////////////////////////////
	    // Преобразование E (результат в K)
	    ///////////////////////////////////////////////////////////////////////////
        private static void E(ulong[] K, ulong[] m)
        {
            // выделить вспомогательный буфер
            ulong[] result = new ulong[m.Length]; 

            // установить начальные условия
            Array.Copy(m, 0, result, 0, m.Length); 

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
        private static void G(ulong[] h, ulong[] m, ulong[] N)
        {
            // выделить вспомогательный буфер
            ulong[] result = new ulong[h.Length]; 

            // выполнить преобразование
            X(h, N, result); LPS(result); E(result, m); 

            // выполнить преобразование
            X(result, m, result); X(result, h, h); 
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Конструктор
	    ///////////////////////////////////////////////////////////////////////////
	    private ulong[] hash;	// текущее хэш-значение
	    private ulong[] N;	    // вспомогательный буфер
	    private ulong[] sum;	// аккумулятор
        private int	    size;	// размер хэш-значения

        public GOSTR3411_2012(int bits) : base()
	    { 
            // сохранить переданные параметры
		    this.size = bits / 8; hash = new ulong[8];

            // выделить память для текущего хэш-значения
            N = new ulong[8]; sum = new ulong[8]; 
	    }
	    // размер блока алгоритма хэширования
	    public override int BlockSize { get { return 64; }}

	    // размер хэш-значения в байтах
	    public override int HashSize { get { return size; }}

	    ///////////////////////////////////////////////////////////////////////////
	    // Вычислить хэш-значение
	    ///////////////////////////////////////////////////////////////////////////
	    public override void Init()
	    {
		    // обнулить стартовое хэш-значение
		    base.Init(); for (int i = 0; i < hash.Length; i++) hash[i] = 0; 
        
            // установить стартовое хэш-значение
            if (size == 32) for (int i = 0; i < hash.Length; i++) 
    	    {
			    // установить фиксированное значение
			    hash[i] = (long)0x0101010101010101L; 
		    }
            // обнулить аккумулятор
		    for (int i = 0; i < N  .Length; i++) N  [i] = 0; 
            for (int i = 0; i < sum.Length; i++) sum[i] = 0;
	    }
	    protected override void Update(byte[] data, int dataOff)
	    {
            // выделить вспомогательный буфер
            ulong[] m = new ulong[hash.Length]; 

            // для всех байтов
            for (int i = 0; i < m.Length; i++)
            {
                m[i] = Math.Convert.ToUInt64(data, dataOff + 8 * i, Endian); 
            }
            // выполнить тактовую функцию
            G(hash, m, N); ADD(N, 512, N); ADD(sum, m, sum); 
        }
	    protected override void Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	    {
            // обработать последний полный блок
            if (dataLen == 64) { Update(data, dataOff);

                // пропустить обработанный блок
                dataOff += 64; dataLen -= 64; 
            }
            // выделить вспомогательный буфер
            ulong[] m = new ulong[hash.Length]; 

            // для всех байтов
            for (int i = 0; i < dataLen; i++)
            {
                // выполнить преобразование данных
                m[i / 8] |= (ulong)(data[dataOff + i] & 0xFF) << ((i % 8) * 8); 
            }
            // выполнить дополнение данных
            m[dataLen / 8] |= (ulong)1 << ((dataLen % 8) * 8);

            // выполнить тактовую функцию
            G(hash, m, N); ADD(N, (ulong)dataLen * 8, N); ADD(sum, m, sum); 

            // выполнить сжатие данных
            G(hash, N, new ulong[8]); G(hash, sum, new ulong[8]); 

            // определить смещение результата
            int offset = hash.Length - size / 8; 

            // для всех 64-разрядных компонентов
            for (int i = 0; i < size / 8; i++)
            {
                // скопировть 64-разрядный компонент
                Math.Convert.FromUInt64(hash[offset + i], Endian, buf, bufOff + i * 8);
            }
        }
#if !STANDALONE
        ////////////////////////////////////////////////////////////////////////////
        // Тесты известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test256(CAPI.Hash algorithm) 
        {
            KnownTest(algorithm, 1, new byte[] {
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
            KnownTest(algorithm, 1, new byte[] {
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
        public static void Test512(CAPI.Hash algorithm)
        {
            KnownTest(algorithm, 1, new byte[] {
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
            KnownTest(algorithm, 1, new byte[] {
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
        public static void TestHMAC256(Mac macAlgorithm) 
        {
            // выполнить тест
            if (KeySizes.Contains(macAlgorithm.KeyFactory.KeySizes, 32))
            Mac.KnownTest(macAlgorithm, new byte[] {
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
        public static void TestHMAC512(Mac macAlgorithm) 
        {
            // выполнить тест
            if (KeySizes.Contains(macAlgorithm.KeyFactory.KeySizes, 32))
            Mac.KnownTest(macAlgorithm, new byte[] {
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
#endif 
    }
}