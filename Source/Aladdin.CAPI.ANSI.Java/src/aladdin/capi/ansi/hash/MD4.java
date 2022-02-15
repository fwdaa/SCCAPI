package aladdin.capi.ansi.hash;
import aladdin.math.*;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования MD4
///////////////////////////////////////////////////////////////////////////////
public class MD4 extends BlockHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    //
    // round 1 left rotates
    //
    private static final int S11 = 3;
    private static final int S12 = 7;
    private static final int S13 = 11;
    private static final int S14 = 19;
    //
    // round 2 left rotates
    //
    private static final int S21 = 3;
    private static final int S22 = 5;
    private static final int S23 = 9;
    private static final int S24 = 13;
    //
    // round 3 left rotates
    //
    private static final int S31 = 3;
    private static final int S32 = 9;
    private static final int S33 = 11;
    private static final int S34 = 15;

    // rotate int x left n bits.
    private static int rotateLeft(int x, int n)
    {
        return (x << n) | (x >>> (32 - n));
    }
    // F, G, H and I are the basic MD4 functions.
    private static int F(int u, int v, int w)
    {
        return (u & v) | (~u & w);
    }
    private static int G(int u, int v, int w)
    {
        return (u & v) | (u & w) | (v & w);
    }
    private static int H(int u, int v, int w)
    {
        return u ^ v ^ w;
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
        a = rotateLeft(a + F(b, c, d) + X[ 0], S11);
        d = rotateLeft(d + F(a, b, c) + X[ 1], S12);
        c = rotateLeft(c + F(d, a, b) + X[ 2], S13);
        b = rotateLeft(b + F(c, d, a) + X[ 3], S14);
        a = rotateLeft(a + F(b, c, d) + X[ 4], S11);
        d = rotateLeft(d + F(a, b, c) + X[ 5], S12);
        c = rotateLeft(c + F(d, a, b) + X[ 6], S13);
        b = rotateLeft(b + F(c, d, a) + X[ 7], S14);
        a = rotateLeft(a + F(b, c, d) + X[ 8], S11);
        d = rotateLeft(d + F(a, b, c) + X[ 9], S12);
        c = rotateLeft(c + F(d, a, b) + X[10], S13);
        b = rotateLeft(b + F(c, d, a) + X[11], S14);
        a = rotateLeft(a + F(b, c, d) + X[12], S11);
        d = rotateLeft(d + F(a, b, c) + X[13], S12);
        c = rotateLeft(c + F(d, a, b) + X[14], S13);
        b = rotateLeft(b + F(c, d, a) + X[15], S14);
        //
        // Round 2 - G cycle, 16 times.
        //
        a = rotateLeft(a + G(b, c, d) + X[ 0] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + X[ 4] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + X[ 8] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + X[12] + 0x5a827999, S24);
        a = rotateLeft(a + G(b, c, d) + X[ 1] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + X[ 5] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + X[ 9] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + X[13] + 0x5a827999, S24);
        a = rotateLeft(a + G(b, c, d) + X[ 2] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + X[ 6] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + X[10] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + X[14] + 0x5a827999, S24);
        a = rotateLeft(a + G(b, c, d) + X[ 3] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + X[ 7] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + X[11] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + X[15] + 0x5a827999, S24);
        //
        // Round 3 - H cycle, 16 times.
        //
        a = rotateLeft(a + H(b, c, d) + X[ 0] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + X[ 8] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + X[ 4] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + X[12] + 0x6ed9eba1, S34);
        a = rotateLeft(a + H(b, c, d) + X[ 2] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + X[10] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + X[ 6] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + X[14] + 0x6ed9eba1, S34);
        a = rotateLeft(a + H(b, c, d) + X[ 1] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + X[ 9] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + X[ 5] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + X[13] + 0x6ed9eba1, S34);
        a = rotateLeft(a + H(b, c, d) + X[ 3] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + X[11] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + X[ 7] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + X[15] + 0x6ed9eba1, S34);

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
            (byte)0x31, (byte)0xd6, (byte)0xcf, (byte)0xe0, 
            (byte)0xd1, (byte)0x6a, (byte)0xe9, (byte)0x31, 
            (byte)0xb7, (byte)0x3c, (byte)0x59, (byte)0xd7, 
            (byte)0xe0, (byte)0xc0, (byte)0x89, (byte)0xc0
        }); 
        knownTest(hashAlgorithm, 1, 
            "a", new byte[] { 
            (byte)0xbd, (byte)0xe5, (byte)0x2c, (byte)0xb3, 
            (byte)0x1d, (byte)0xe3, (byte)0x3e, (byte)0x46, 
            (byte)0x24, (byte)0x5e, (byte)0x05, (byte)0xfb, 
            (byte)0xdb, (byte)0xd6, (byte)0xfb, (byte)0x24
        }); 
        knownTest(hashAlgorithm, 1, 
            "abc", new byte[] { 
            (byte)0xa4, (byte)0x48, (byte)0x01, (byte)0x7a, 
            (byte)0xaf, (byte)0x21, (byte)0xd8, (byte)0x52, 
            (byte)0x5f, (byte)0xc1, (byte)0x0a, (byte)0xe8, 
            (byte)0x7a, (byte)0xa6, (byte)0x72, (byte)0x9d
        }); 
        knownTest(hashAlgorithm, 1, 
            "message digest", new byte[] { 
            (byte)0xd9, (byte)0x13, (byte)0x0a, (byte)0x81, 
            (byte)0x64, (byte)0x54, (byte)0x9f, (byte)0xe8, 
            (byte)0x18, (byte)0x87, (byte)0x48, (byte)0x06, 
            (byte)0xe1, (byte)0xc7, (byte)0x01, (byte)0x4b
        }); 
        knownTest(hashAlgorithm, 1, 
            "abcdefghijklmnopqrstuvwxyz", new byte[] { 
            (byte)0xd7, (byte)0x9e, (byte)0x1c, (byte)0x30, 
            (byte)0x8a, (byte)0xa5, (byte)0xbb, (byte)0xcd, 
            (byte)0xee, (byte)0xa8, (byte)0xed, (byte)0x63, 
            (byte)0xdf, (byte)0x41, (byte)0x2d, (byte)0xa9
        }); 
        knownTest(hashAlgorithm, 1, 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + 
            "abcdefghijklmnopqrstuvwxyz0123456789", new byte[] { 
            (byte)0x04, (byte)0x3f, (byte)0x85, (byte)0x82, 
            (byte)0xf2, (byte)0x41, (byte)0xdb, (byte)0x35, 
            (byte)0x1c, (byte)0xe6, (byte)0x27, (byte)0xe1, 
            (byte)0x53, (byte)0xe7, (byte)0xf0, (byte)0xe4
        }); 
        knownTest(hashAlgorithm, 1, 
            "1234567890123456789012345678901234567890" + 
            "1234567890123456789012345678901234567890", new byte[] { 
            (byte)0xe3, (byte)0x3b, (byte)0x4d, (byte)0xdc, 
            (byte)0x9c, (byte)0x38, (byte)0xf2, (byte)0x19, 
            (byte)0x9c, (byte)0x3e, (byte)0x7b, (byte)0x16, 
            (byte)0x4f, (byte)0xcc, (byte)0x05, (byte)0x36
        }); 
    }
}
