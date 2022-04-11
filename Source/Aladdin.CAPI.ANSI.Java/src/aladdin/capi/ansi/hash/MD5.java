package aladdin.capi.ansi.hash;
import aladdin.math.*;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования MD5
///////////////////////////////////////////////////////////////////////////////
public class MD5 extends BlockHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    //
    // round 1 left rotates
    //
    private static final int S11 = 7;
    private static final int S12 = 12;
    private static final int S13 = 17;
    private static final int S14 = 22;
    //
    // round 2 left rotates
    //
    private static final int S21 = 5;
    private static final int S22 = 9;
    private static final int S23 = 14;
    private static final int S24 = 20;
    //
    // round 3 left rotates
    //
    private static final int S31 = 4;
    private static final int S32 = 11;
    private static final int S33 = 16;
    private static final int S34 = 23;
    //
    // round 4 left rotates
    //
    private static final int S41 = 6;
    private static final int S42 = 10;
    private static final int S43 = 15;
    private static final int S44 = 21;

    // rotate int x left n bits.
    private static int rotateLeft(int x, int n)
    {
        return (x << n) | (x >>> (32 - n));
    }
    // F, G, H and I are the basic MD5 functions.
    private static int F(int u, int v, int w)
    {
        return (u & v) | (~u & w);
    }
    private static int G(int u, int v, int w)
    {
        return (u & w) | (v & ~w);
    }
    private static int H(int u, int v, int w)
    {
        return u ^ v ^ w;
    }
    private static int K(int u, int v, int w)
    {
        return v ^ (u | ~w);
    }
    private long byteCount; private int H1, H2, H3, H4;

    // размер хэш-значения в байтах
	@Override public int hashSize() { return 16; }  
	
	// размер блока в байтах
	@Override public int blockSize() { return 64; } 

	// инициализировать алгоритм
	@Override public void init() throws IOException
    { 
        super.init(); byteCount = 0;  

        H1 = 0x67452301; H2 = 0xefcdab89;
        H3 = 0x98badcfe; H4 = 0x10325476;
    }
	// обработать блок данных
	@Override protected void update(byte[] data, int dataOff)  
    {
        // выделить буфер требуемого размера
        int[] X = new int[16]; byteCount += blockSize();
        
        // скопировать данные в буфер
        for (int i = 0; i < X.length; i++)
        {
            // скопировать данные в буфер
            X[i] = Convert.toInt32(data, dataOff + 4 * i, ENDIAN); 
        }
        int a = H1; int b = H2; int c = H3; int d = H4;
        //
        // Round 1 - F cycle, 16 times.
        //
        a = rotateLeft(a + F(b, c, d) + X[ 0] + 0xd76aa478, S11) + b;
        d = rotateLeft(d + F(a, b, c) + X[ 1] + 0xe8c7b756, S12) + a;
        c = rotateLeft(c + F(d, a, b) + X[ 2] + 0x242070db, S13) + d;
        b = rotateLeft(b + F(c, d, a) + X[ 3] + 0xc1bdceee, S14) + c;
        a = rotateLeft(a + F(b, c, d) + X[ 4] + 0xf57c0faf, S11) + b;
        d = rotateLeft(d + F(a, b, c) + X[ 5] + 0x4787c62a, S12) + a;
        c = rotateLeft(c + F(d, a, b) + X[ 6] + 0xa8304613, S13) + d;
        b = rotateLeft(b + F(c, d, a) + X[ 7] + 0xfd469501, S14) + c;
        a = rotateLeft(a + F(b, c, d) + X[ 8] + 0x698098d8, S11) + b;
        d = rotateLeft(d + F(a, b, c) + X[ 9] + 0x8b44f7af, S12) + a;
        c = rotateLeft(c + F(d, a, b) + X[10] + 0xffff5bb1, S13) + d;
        b = rotateLeft(b + F(c, d, a) + X[11] + 0x895cd7be, S14) + c;
        a = rotateLeft(a + F(b, c, d) + X[12] + 0x6b901122, S11) + b;
        d = rotateLeft(d + F(a, b, c) + X[13] + 0xfd987193, S12) + a;
        c = rotateLeft(c + F(d, a, b) + X[14] + 0xa679438e, S13) + d;
        b = rotateLeft(b + F(c, d, a) + X[15] + 0x49b40821, S14) + c;
        //
        // Round 2 - G cycle, 16 times.
        //
        a = rotateLeft(a + G(b, c, d) + X[ 1] + 0xf61e2562, S21) + b;
        d = rotateLeft(d + G(a, b, c) + X[ 6] + 0xc040b340, S22) + a;
        c = rotateLeft(c + G(d, a, b) + X[11] + 0x265e5a51, S23) + d;
        b = rotateLeft(b + G(c, d, a) + X[ 0] + 0xe9b6c7aa, S24) + c;
        a = rotateLeft(a + G(b, c, d) + X[ 5] + 0xd62f105d, S21) + b;
        d = rotateLeft(d + G(a, b, c) + X[10] + 0x02441453, S22) + a;
        c = rotateLeft(c + G(d, a, b) + X[15] + 0xd8a1e681, S23) + d;
        b = rotateLeft(b + G(c, d, a) + X[ 4] + 0xe7d3fbc8, S24) + c;
        a = rotateLeft(a + G(b, c, d) + X[ 9] + 0x21e1cde6, S21) + b;
        d = rotateLeft(d + G(a, b, c) + X[14] + 0xc33707d6, S22) + a;
        c = rotateLeft(c + G(d, a, b) + X[ 3] + 0xf4d50d87, S23) + d;
        b = rotateLeft(b + G(c, d, a) + X[ 8] + 0x455a14ed, S24) + c;
        a = rotateLeft(a + G(b, c, d) + X[13] + 0xa9e3e905, S21) + b;
        d = rotateLeft(d + G(a, b, c) + X[ 2] + 0xfcefa3f8, S22) + a;
        c = rotateLeft(c + G(d, a, b) + X[ 7] + 0x676f02d9, S23) + d;
        b = rotateLeft(b + G(c, d, a) + X[12] + 0x8d2a4c8a, S24) + c;
        //
        // Round 3 - H cycle, 16 times.
        //
        a = rotateLeft(a + H(b, c, d) + X[ 5] + 0xfffa3942, S31) + b;
        d = rotateLeft(d + H(a, b, c) + X[ 8] + 0x8771f681, S32) + a;
        c = rotateLeft(c + H(d, a, b) + X[11] + 0x6d9d6122, S33) + d;
        b = rotateLeft(b + H(c, d, a) + X[14] + 0xfde5380c, S34) + c;
        a = rotateLeft(a + H(b, c, d) + X[ 1] + 0xa4beea44, S31) + b;
        d = rotateLeft(d + H(a, b, c) + X[ 4] + 0x4bdecfa9, S32) + a;
        c = rotateLeft(c + H(d, a, b) + X[ 7] + 0xf6bb4b60, S33) + d;
        b = rotateLeft(b + H(c, d, a) + X[10] + 0xbebfbc70, S34) + c;
        a = rotateLeft(a + H(b, c, d) + X[13] + 0x289b7ec6, S31) + b;
        d = rotateLeft(d + H(a, b, c) + X[ 0] + 0xeaa127fa, S32) + a;
        c = rotateLeft(c + H(d, a, b) + X[ 3] + 0xd4ef3085, S33) + d;
        b = rotateLeft(b + H(c, d, a) + X[ 6] + 0x04881d05, S34) + c;
        a = rotateLeft(a + H(b, c, d) + X[ 9] + 0xd9d4d039, S31) + b;
        d = rotateLeft(d + H(a, b, c) + X[12] + 0xe6db99e5, S32) + a;
        c = rotateLeft(c + H(d, a, b) + X[15] + 0x1fa27cf8, S33) + d;
        b = rotateLeft(b + H(c, d, a) + X[ 2] + 0xc4ac5665, S34) + c;
        //
        // Round 4 - K cycle, 16 times.
        //
        a = rotateLeft(a + K(b, c, d) + X[ 0] + 0xf4292244, S41) + b;
        d = rotateLeft(d + K(a, b, c) + X[ 7] + 0x432aff97, S42) + a;
        c = rotateLeft(c + K(d, a, b) + X[14] + 0xab9423a7, S43) + d;
        b = rotateLeft(b + K(c, d, a) + X[ 5] + 0xfc93a039, S44) + c;
        a = rotateLeft(a + K(b, c, d) + X[12] + 0x655b59c3, S41) + b;
        d = rotateLeft(d + K(a, b, c) + X[ 3] + 0x8f0ccc92, S42) + a;
        c = rotateLeft(c + K(d, a, b) + X[10] + 0xffeff47d, S43) + d;
        b = rotateLeft(b + K(c, d, a) + X[ 1] + 0x85845dd1, S44) + c;
        a = rotateLeft(a + K(b, c, d) + X[ 8] + 0x6fa87e4f, S41) + b;
        d = rotateLeft(d + K(a, b, c) + X[15] + 0xfe2ce6e0, S42) + a;
        c = rotateLeft(c + K(d, a, b) + X[ 6] + 0xa3014314, S43) + d;
        b = rotateLeft(b + K(c, d, a) + X[13] + 0x4e0811a1, S44) + c;
        a = rotateLeft(a + K(b, c, d) + X[ 4] + 0xf7537e82, S41) + b;
        d = rotateLeft(d + K(a, b, c) + X[11] + 0xbd3af235, S42) + a;
        c = rotateLeft(c + K(d, a, b) + X[ 2] + 0x2ad7d2bb, S43) + d;
        b = rotateLeft(b + K(c, d, a) + X[ 9] + 0xeb86d391, S44) + c;

        H1 += a; H2 += b; H3 += c; H4 += d;
    }
	// завершить преобразование
	@Override protected void finish(
        byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
    {
        // для последнего полного блока 
        int blockSize = blockSize(); if (dataLen == blockSize) 
        {
            // обработать последний полный блок
            update(data, dataOff); dataOff += blockSize; dataLen -= blockSize;
        }
        // определить размер данных в битах
        long bitLength = ((byteCount + dataLen) << 3);
        
        // выделить буфер для дополнения
        byte[] buffer = new byte[blockSize]; buffer[dataLen] = (byte)0x80;
        
        // скопировать данные
        System.arraycopy(data, dataOff, buffer, 0, dataLen);

        // обработать дополненный блок
        if (dataLen >= 56) { update(buffer, 0);

            // обнулить обработанный блок
            for (int i = 0; i < 56; i++) buffer[i] = 0; 
        }
        // обработать размер 
        Convert.fromInt64(bitLength, ENDIAN, buffer, 56); update(buffer, 0);
        
        // извлечь хэш-значение
        Convert.fromInt32(H1, ENDIAN, buf, bufOff +  0); 
        Convert.fromInt32(H2, ENDIAN, buf, bufOff +  4); 
        Convert.fromInt32(H3, ENDIAN, buf, bufOff +  8); 
        Convert.fromInt32(H4, ENDIAN, buf, bufOff + 12); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Hash hashAlgorithm) throws Exception
    {
        knownTest(hashAlgorithm, 1, 
            "", new byte[] { 
            (byte)0xd4, (byte)0x1d, (byte)0x8c, (byte)0xd9, 
            (byte)0x8f, (byte)0x00, (byte)0xb2, (byte)0x04, 
            (byte)0xe9, (byte)0x80, (byte)0x09, (byte)0x98, 
            (byte)0xec, (byte)0xf8, (byte)0x42, (byte)0x7e
        }); 
        knownTest(hashAlgorithm, 1, 
            "a", new byte[] { 
            (byte)0x0c, (byte)0xc1, (byte)0x75, (byte)0xb9, 
            (byte)0xc0, (byte)0xf1, (byte)0xb6, (byte)0xa8, 
            (byte)0x31, (byte)0xc3, (byte)0x99, (byte)0xe2, 
            (byte)0x69, (byte)0x77, (byte)0x26, (byte)0x61
        }); 
        knownTest(hashAlgorithm, 1, 
            "abc", new byte[] { 
            (byte)0x90, (byte)0x01, (byte)0x50, (byte)0x98, 
            (byte)0x3c, (byte)0xd2, (byte)0x4f, (byte)0xb0, 
            (byte)0xd6, (byte)0x96, (byte)0x3f, (byte)0x7d, 
            (byte)0x28, (byte)0xe1, (byte)0x7f, (byte)0x72
        }); 
        knownTest(hashAlgorithm, 1, 
            "message digest", new byte[] { 
            (byte)0xf9, (byte)0x6b, (byte)0x69, (byte)0x7d, 
            (byte)0x7c, (byte)0xb7, (byte)0x93, (byte)0x8d, 
            (byte)0x52, (byte)0x5a, (byte)0x2f, (byte)0x31, 
            (byte)0xaa, (byte)0xf1, (byte)0x61, (byte)0xd0
        }); 
        knownTest(hashAlgorithm, 1, 
            "abcdefghijklmnopqrstuvwxyz", new byte[] { 
            (byte)0xc3, (byte)0xfc, (byte)0xd3, (byte)0xd7, 
            (byte)0x61, (byte)0x92, (byte)0xe4, (byte)0x00, 
            (byte)0x7d, (byte)0xfb, (byte)0x49, (byte)0x6c, 
            (byte)0xca, (byte)0x67, (byte)0xe1, (byte)0x3b
        }); 
        knownTest(hashAlgorithm, 1, 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + 
            "abcdefghijklmnopqrstuvwxyz0123456789", new byte[] { 
            (byte)0xd1, (byte)0x74, (byte)0xab, (byte)0x98, 
            (byte)0xd2, (byte)0x77, (byte)0xd9, (byte)0xf5, 
            (byte)0xa5, (byte)0x61, (byte)0x1c, (byte)0x2c, 
            (byte)0x9f, (byte)0x41, (byte)0x9d, (byte)0x9f
        }); 
        knownTest(hashAlgorithm, 1, 
            "1234567890123456789012345678901234567890" + 
            "1234567890123456789012345678901234567890", new byte[] { 
            (byte)0x57, (byte)0xed, (byte)0xf4, (byte)0xa2, 
            (byte)0x2b, (byte)0xe3, (byte)0xc9, (byte)0x55, 
            (byte)0xac, (byte)0x49, (byte)0xda, (byte)0x2e, 
            (byte)0x21, (byte)0x07, (byte)0xb6, (byte)0x7a
        }); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // HMAC
    ////////////////////////////////////////////////////////////////////////////
    public static void testHMAC(Mac algorithm) throws Exception
    {
        int[] keySizes = algorithm.keyFactory().keySizes(); 
        
        if (KeySizes.contains(keySizes, 16))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
        }, 1, "Hi There", new byte[] {
            (byte)0x92, (byte)0x94, (byte)0x72, (byte)0x7a, 
            (byte)0x36, (byte)0x38, (byte)0xbb, (byte)0x1c, 
            (byte)0x13, (byte)0xf4, (byte)0x8e, (byte)0xf8, 
            (byte)0x15, (byte)0x8b, (byte)0xfc, (byte)0x9d
        }); 
        if (KeySizes.contains(keySizes, 4))
        Mac.knownTest(algorithm, "Jefe".getBytes("UTF-8"), 
            1, "what do ya want for nothing?", new byte[] {
            (byte)0x75, (byte)0x0c, (byte)0x78, (byte)0x3e, 
            (byte)0x6a, (byte)0xb0, (byte)0xb5, (byte)0x03, 
            (byte)0xea, (byte)0xa8, (byte)0x6e, (byte)0x31, 
            (byte)0x0a, (byte)0x5d, (byte)0xb7, (byte)0x38
        }); 
        if (KeySizes.contains(keySizes, 16))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
        }, 50, new byte[] { (byte)0xDD }, new byte[] {
            (byte)0x56, (byte)0xbe, (byte)0x34, (byte)0x52, 
            (byte)0x1d, (byte)0x14, (byte)0x4c, (byte)0x88, 
            (byte)0xdb, (byte)0xb8, (byte)0xc7, (byte)0x33, 
            (byte)0xf0, (byte)0xe8, (byte)0xb3, (byte)0xf6
        }); 
        if (KeySizes.contains(keySizes, 16))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
        }, 1, "Test With Truncation", new byte[] {
            (byte)0x56, (byte)0x46, (byte)0x1e, (byte)0xf2, 
            (byte)0x34, (byte)0x2e, (byte)0xdc, (byte)0x00, 
            (byte)0xf9, (byte)0xba, (byte)0xb9, (byte)0x95, 
            (byte)0x69, (byte)0x0e, (byte)0xfd, (byte)0x4c
        }); 
        if (KeySizes.contains(keySizes, 80))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
        }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
            (byte)0x6b, (byte)0x1a, (byte)0xb7, (byte)0xfe, 
            (byte)0x4b, (byte)0xd7, (byte)0xbf, (byte)0x8f, 
            (byte)0x0b, (byte)0x62, (byte)0xe6, (byte)0xce, 
            (byte)0x61, (byte)0xb9, (byte)0xd0, (byte)0xcd        
        }); 
        if (KeySizes.contains(keySizes, 80))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
        }, 1, "Test Using Larger Than Block-Size Key and Larger " + 
            "Than One Block-Size Data", new byte[] {
            (byte)0x6f, (byte)0x63, (byte)0x0f, (byte)0xad, 
            (byte)0x67, (byte)0xcd, (byte)0xa0, (byte)0xee, 
            (byte)0x1f, (byte)0xb1, (byte)0xf5, (byte)0x62, 
            (byte)0xdb, (byte)0x3a, (byte)0xa5, (byte)0x3e        
        }); 
    }
}
