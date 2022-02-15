package aladdin.capi.stb.hash;
import aladdin.math.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования СТБ 1176.1
///////////////////////////////////////////////////////////////////////////
public class STB11761 extends BlockHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
	//////////////////////////////////////////////////////////////////////////////
	// Используемые константы
	//////////////////////////////////////////////////////////////////////////////
	private static final int[] StartV =
	{
		0xd1845ac6, 0xac3d25c6, 0xf467247d, 0x079294ab,
		0xf19a24cd, 0xb47d25c6, 0xd4522491, 0x0d817489,
		0x87d45a6f, 0x3d5721c6, 0x573714c8, 0x078274db,
		0x2a8a1a76, 0xdc6715c6, 0xb4f1257d, 0x0b1294ac
	};
	private static final int[] T1 =
	{
		0xaa2aa82e, 0x8a0a088e, 0xa222a026, 0x82020086,
		0xae2cac28, 0x8c0e0c88, 0xa624a420, 0x84061e9a,
		0xab2ba92f, 0x8b0b098f, 0xa323a127, 0xb32133a7,
		0x8d0f9f1b, 0xaf2d3fbb, 0x07870583, 0x17859d19,
		0xba3ab83e, 0x98381abe, 0xb231b025, 0x806312a5,
		0xad3dbf29, 0x89b94b6f, 0xbd3cef6a, 0xcfbc1532,
		0xeb3be96d, 0x9b396bcd, 0xb130e336, 0xe11003b6,
		0x9e1c9c18, 0xeaca4a6e, 0x4edf4c99, 0x5e7fb481,
		0xe868fa6c, 0xc8485ace, 0xe262e034, 0x92424096,
		0xee7eec7a, 0xdd0d1fcb, 0xe666e460, 0x971d4f93,
		0xfb697bed, 0xc949db4d, 0xf36137f1, 0x0173b771,
		0x5b5c0459, 0xcc5f5d16, 0x47945291, 0x35fef813,
		0xf272787c, 0x907058fc, 0x147946b5, 0xdad9c267,
		0xe765e511, 0xc0f0437d, 0xf764c344, 0xc6fff9c4,
		0xf5775654, 0x9545fd75, 0xc1d8d376, 0xc77441de,
		0xd25351d0, 0xc5d7d5f6, 0x50d6d157, 0xd455dcf4
	};
	private static final int[] T3 =
	{
		0x4dcdcf4f, 0x69e9eb6b, 0x65e5e767, 0x41c1c343,
		0x49c9cb4b, 0x6dedef6f, 0x61e1e363, 0x45c5c747,
		0x5dddcc4c, 0x79f9e868, 0xf17140c0, 0xd55564e4,
		0x51d1c242, 0x75f5ec6c, 0xfd7d4ece, 0xd95960ea,
		0x5cdcde5e, 0x6af8fa78, 0x66e6e062, 0x48c88c0c,
		0x7aa8aa28, 0x8e0e4aca, 0x53d3c444, 0xff7f6eee,
		0x1c9cdf5f, 0x2ab8fb7b, 0xe2700181, 0x9e0d7cad,
		0x72f48357, 0x46d0a92d, 0x8d5b0fdb, 0xf3747e91,
		0x54c6d456, 0x20f0f222, 0x2cfc1efe, 0x58d838ba,
		0x50d28052, 0x30a0a232, 0x3a825ada, 0x08889092,
		0x04d6d705, 0x73a1acae, 0xbc0aab1d, 0x8f2f842e,
		0x188a8909, 0x29b9f63d, 0xa406f721, 0x853f8677,
		0x07879515, 0x23bba32b, 0xa5af1a98, 0x009a25bd,
		0x31b19303, 0x0b19a7b5, 0x3c3e14bf, 0xb33927b7,
		0x1f117624, 0x26948b35, 0x991b9b97, 0x9d34963b,
		0x3337b0be, 0x02101716, 0x12a69fb4, 0xb61336b2
	};
	private static final int[] T5 =
	{
		0x5557455d, 0x4715547c, 0x5644465c, 0x1416177d,
		0x51534159, 0x43115078, 0x7072607a, 0xf8faf9d1,
		0x5f4d4f05, 0x1d1f5ef4, 0x585a4852, 0x4a185bf1,
		0x494b1913, 0x1b091af0, 0x7e6c6e74, 0xf6e4f50d,
		0x7577657f, 0x6735764c, 0x64626668, 0x3430710f,
		0x7332616a, 0x63313840, 0x420710d8, 0xdadcd5fb,
		0xfdffedf7, 0xefbdde36, 0xe8fceae6, 0xb8fedd33,
		0xe9baeba8, 0xd9dbf212, 0x4e0b2408, 0xb4e0c83c,
		0xd7c5c726, 0x9597d03a, 0xd4d6c41c, 0xc694d379,
		0xc1c3917b, 0x9381963e, 0xe2b0f369, 0x282a2c84,
		0xdfcdcfe1, 0xccd2b99d, 0xaa9fb28d, 0xbbe58521,
		0xc9cb9901, 0xca86bf9b, 0xce9c87a9, 0x6d03abc0,
		0xe7b5b76f, 0xa5a7a00a, 0xb6a29e2e, 0xa4a6e38c,
		0xb18eb389, 0xa1a3ec04, 0xc2ee8b98, 0x9a880020,
		0x372527ad, 0x8a6b223d, 0x02061e90, 0xbc0c0e23,
		0xbe928fac, 0x80af3f83, 0x39ae823b, 0x2d292f2b
	};
	private static final int[] T7 =
	{
		0xb2b03212, 0x921a13bf, 0xbab83a18, 0x9a101bb7,
		0xb6b43616, 0x961e17bb, 0xbebc1c3e, 0x9e143f11,
		0xb3b13303, 0x931902ae, 0xbdaf3715, 0x9f0706aa,
		0xb5a73505, 0x970e04b9, 0xaba90131, 0x9b0a3057,
		0xa2a02200, 0x900853ad, 0xa8fa380c, 0x98520ba3,
		0xa6a43455, 0x943c1f82, 0xacfe5623, 0x9c263d24,
		0xa1217391, 0x839d502a, 0xfc2e7680, 0x8ed2473b,
		0x954599f6, 0xa58a2c74, 0x885a288f, 0xf8ff092f,
		0xf2f02042, 0xd05851fd, 0xeae87a4a, 0xda405bf7,
		0xf4f5668b, 0x861d890f, 0x7e2dd8fb, 0x5e87f984,
		0xf3f17143, 0x8159d3ee, 0xefe7e58d, 0xec7cdfdb,
		0xdde62754, 0x850d4625, 0x3972776e, 0x78e2416c,
		0xe06a6444, 0xc248d9eb, 0x685fcb2b, 0xcac95d29,
		0xe44fc870, 0x7bede975, 0x4d7f7dc0, 0x8c67ded7,
		0xe36365d5, 0xd1c76fe1, 0xc379625c, 0x4ed6606d,
		0xcfdc6b4b, 0x69cdd4ce, 0xc649614c, 0xc5ccc1c4
	};
	//////////////////////////////////////////////////////////////////////////////
	// Вспомогательные функции
	//////////////////////////////////////////////////////////////////////////////
	private static void rho(int[] V, int[] T)
	{
		for(int i =  0; i < 29; i++) V[i + 16] = (V[i] ^ V[i + 3] ^ V[i + 13] ^ V[i + 15]) + 0x2bda732e;
		for(int i = 29; i < 47; i++) V[i + 16] = (V[i] ^ V[i + 2] ^ V[i + 15]            ) + 0x3920fe85;
		for(int i = 47; i < 66; i++) V[i + 16] = (V[i] ^ V[i + 4] ^ V[i +  9]            ) + 0xbc1641f9;
		for(int i = 66; i < 83; i++) V[i + 16] = (V[i] ^ V[i + 8] ^ V[i + 13]            ) + 0x75fe243b;

        System.arraycopy(V, 29, T,  0, 16);
		System.arraycopy(V, 47, T, 16, 16);
		System.arraycopy(V, 66, T, 32, 16);
		System.arraycopy(V, 83, T, 48, 16);
		System.arraycopy(T, 48, V,  0, 16);
	}
	private static void omega(int[] X, int xOff, int[] Y0, int[] Y1, int[] Y2,
		 int[] Y3, int[] Y4, int[] Y5, int[] Y6, int[] Y7)
	{
		byte[] y0 = new byte[256]; byte[] y1 = new byte[256]; 
		byte[] y2 = new byte[256]; byte[] y3 = new byte[256];
		byte[] y4 = new byte[256]; byte[] y5 = new byte[256]; 
		byte[] y6 = new byte[256]; byte[] y7 = new byte[256];

		for (int i = 0; i < 8 * X.length; i++)
		{
            Convert.fromInt32(Y0[i], ENDIAN, y0, i * 4); 
            Convert.fromInt32(Y1[i], ENDIAN, y1, i * 4); 
            Convert.fromInt32(Y2[i], ENDIAN, y2, i * 4); 
            Convert.fromInt32(Y3[i], ENDIAN, y3, i * 4); 
            Convert.fromInt32(Y4[i], ENDIAN, y4, i * 4); 
            Convert.fromInt32(Y5[i], ENDIAN, y5, i * 4); 
            Convert.fromInt32(Y6[i], ENDIAN, y6, i * 4); 
            Convert.fromInt32(Y7[i], ENDIAN, y7, i * 4); 
		}
		for (int m = 0; m < 32; m++)
		{
			// вычисляем вектор подстановок
			int P0  = ((y0[(X[xOff + 0]       ) & 0xFF] & 0xFF)      );
				P0 |= ((y1[(X[xOff + 0] >>>  8) & 0xFF] & 0xFF) <<  8);
				P0 |= ((y2[(X[xOff + 0] >>> 16) & 0xFF] & 0xFF) << 16);
				P0 |= ((y3[(X[xOff + 0] >>> 24) & 0xFF] & 0xFF) << 24);
			int P1  = ((y4[(X[xOff + 1]       ) & 0xFF] & 0xFF)      );
				P1 |= ((y5[(X[xOff + 1] >>>  8) & 0xFF] & 0xFF) <<  8);
				P1 |= ((y6[(X[xOff + 1] >>> 16) & 0xFF] & 0xFF) << 16);
				P1 |= ((y7[(X[xOff + 1] >>> 24) & 0xFF] & 0xFF) << 24);

			// циклический сдвиг на 3 разряда влево
			int Carry = P1 >>> 29; P1 = (P1 << 3) | (P0 >>> 29); P0 = (P0 << 3) | Carry;

			// логически складываем и меняем местами
			P0         ^= X[xOff + 2]; P1         ^= X[xOff + 3];
			X[xOff + 2] = X[xOff + 0]; X[xOff + 3] = X[xOff + 1];
			X[xOff + 0] = P0;          X[xOff + 1] = P1;
		}
	}
	private static void powerXi(int[] WI, int[] WO)
	{
		WO[7] = WI[0] ^ WI[2];
		WO[2] = WI[0] ^ WI[4] ^ WI[6];
		WO[3] = WI[1] ^ WI[5] ^ WI[7];
		WO[6] = WO[7] ^ WI[1] ^ WI[4] ^ WI[7];
		WO[5] = WO[6] ^ WI[0] ^ WI[3] ^ WI[6];
		WO[4] = WO[5] ^ WI[0] ^ WI[4] ^ WI[5] ^ WI[7];
		WO[1] = WO[4] ^ WI[1] ^ WI[4] ^ WI[6] ^ WI[7];
		WO[0] = WO[5] ^ WO[7] ^ WI[4];
	}
	private static void doublePhi(int[] H, int hOff, int[] W)
	{
		int Temp = 0;
		for (int j = 0; j < 4; j++)
		{
			Temp     = (W[j] + H[hOff + j]) ^ W[j + 4];
			W[j + 0] = (Temp + H[hOff + j]) ^ W[j + 0];
			W[j + 4] = Temp;
		}
	}
	//////////////////////////////////////////////////////////////////////////////
	// Конструктор
	//////////////////////////////////////////////////////////////////////////////
	private final byte[] start;     // стартовое значение
	private final int[]  hash;      // текущее хэш-значение
	private final int[]  vec;   	// вспомогательный вектор
	private       long   length;	// размер данных

    public STB11761(byte[] start) 
	{ 
		// сохранить переданные параметры
		super(); this.start = start;
 
		// выделить память для текущего хэш-значения
		hash = new int[8]; vec = new int[99]; 
	}
	// размер блока алгоритма хэширования
	@Override public int blockSize() { return 32; }

    // размер хэш-значения в байтах
	@Override public int hashSize() { return 32; }

	//////////////////////////////////////////////////////////////////////////////
	// Обработка одного блока
	//////////////////////////////////////////////////////////////////////////////
	private void processBlock(int[] src, int srcOff)
	{
		// временные переменные
		int[] T0 = new int[64]; int[] T2 = new int[64];
		int[] T4 = new int[64]; int[] T6 = new int[64];
		int[] WI = new int[ 8]; int[] WO = new int[ 8];

		// начальное значение вектора V для вычисления T0,T2,T4,T6
		for (int i = 0; i < 8; i++)
		{
			vec[i    ] += src [i + srcOff];
			vec[i + 8] += hash[i];
		}
		// вычислить T0 / T2 / T4  / T6
		rho(vec, T0); rho(vec, T2);
		rho(vec, T4); rho(vec, T6);

		// начальное значение переменной W
		for (int i = 0; i < 8; i++)  WI[i] = src [i + srcOff] ^ hash[i];

		// преобразование w
		omega(WI, 0, T0, T1, T2, T3, T4, T5, T6, T7);
		omega(WI, 4, T4, T1, T0, T3, T6, T5, T2, T7);

        // преобразование  xi^31
		powerXi(WI, WO);

		// преобразования phi^2
		doublePhi(hash, 0, WO); doublePhi(src, srcOff + 0, WO);
		doublePhi(hash, 4, WO); doublePhi(src, srcOff + 4, WO);

		// запоминаем стартовое значение для следующего блока
		System.arraycopy(WO, 0, hash, 0, 8);
	}
	//////////////////////////////////////////////////////////////////////////////
	// Вычислить хэш-значение
	//////////////////////////////////////////////////////////////////////////////
	@Override public void init() throws IOException
	{
		// инициализировать алгоритм
		super.init(); length = 0; System.arraycopy(StartV, 0, vec, 0, StartV.length); 
        
		// для всех четверок байтов
		for (int i = 0; i < start.length / 4; i++)
		{
			// преобразовать в число
			hash[i] = Convert.toInt32(start, i * 4, ENDIAN); 
		}
	}
	@Override protected void update(byte[] src, int srcOff)
	{
		// создать временные переменные
		int[] srcI = new int[blockSize() / 4];  

		// для всех четверок байтов
		for (int i = 0; i < srcI.length; i++)
		{
			// преобразовать формат исходных данных
			srcI[i] = Convert.toInt32(src, srcOff + i * 4, ENDIAN); 
		}
		// обработать полный блок
		processBlock(srcI, 0); length += 32;
	}
	@Override protected void finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	{
		// дополнить неполный блок нулями
		byte[] buffer = new byte[blockSize()]; System.arraycopy(data, dataOff, buffer, 0, dataLen);

		// обработать неполный блок
		update(buffer, 0); length -= buffer.length - dataLen;

		// закодировать размер в байтах
        Convert.fromInt64(length, ENDIAN, buffer, 0); 
        
		// дополнить блок нулями
		for (int i = 8; i < buffer.length; i++) buffer[i] = 0;

		// обработать размер всех данных в байтах
		update(buffer, 0); length -= buffer.length;
        
		// для всех четверок байтов
		for (int i = 0; i < buffer.length / 4; i++)
		{
			// извлечь отдельные байты
            Convert.fromInt32(hash[i], ENDIAN, buf, bufOff + i * 4); 
		}
	}
	///////////////////////////////////////////////////////////////////////////
	// Тест известного ответа
	///////////////////////////////////////////////////////////////////////////
    public static void test(Hash hashAlgorithm) throws Exception
    {
        knownTest(hashAlgorithm, 1, new byte[] {
            (byte)0x46, (byte)0x69, (byte)0x66, (byte)0x74,
            (byte)0x79,	(byte)0x20,	(byte)0x66,	(byte)0x6f,
            (byte)0x75,	(byte)0x72,	(byte)0x20,	(byte)0x62,
            (byte)0x79,	(byte)0x74,	(byte)0x65,	(byte)0x20,
            (byte)0x6f,	(byte)0x72,	(byte)0x20,	(byte)0x66,
            (byte)0x6f,	(byte)0x75,	(byte)0x72,	(byte)0x20,
            (byte)0x68,	(byte)0x75,	(byte)0x6e,	(byte)0x64,
            (byte)0x72,	(byte)0x65,	(byte)0x64,	(byte)0x20,
            (byte)0x74,	(byte)0x68,	(byte)0x69,	(byte)0x72,
            (byte)0x74,	(byte)0x79,	(byte)0x20,	(byte)0x74,
            (byte)0x77,	(byte)0x6f,	(byte)0x20,	(byte)0x62,
            (byte)0x69,	(byte)0x74,	(byte)0x20,	(byte)0x6d,
            (byte)0x65,	(byte)0x73,	(byte)0x73,	(byte)0x61,
            (byte)0x67,	(byte)0x65
        }, new byte[] {
            (byte)0x5d, (byte)0xee, (byte)0x9a, (byte)0x92,
            (byte)0x81, (byte)0x12, (byte)0x6c, (byte)0xee,
            (byte)0x5f, (byte)0x67, (byte)0x63, (byte)0x0e,
            (byte)0x25, (byte)0x1f, (byte)0x33, (byte)0x33,
            (byte)0x86, (byte)0xab, (byte)0x09, (byte)0x22,
            (byte)0x6c, (byte)0xc0, (byte)0xc5, (byte)0x36,
            (byte)0xe6, (byte)0xdd, (byte)0x44, (byte)0x4b,
            (byte)0x83, (byte)0xbe, (byte)0xd3, (byte)0x67
        }); 
    }
}
