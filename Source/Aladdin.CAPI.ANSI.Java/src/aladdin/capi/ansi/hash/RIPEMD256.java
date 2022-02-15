package aladdin.capi.ansi.hash;
import aladdin.math.*;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования RIPEMD256
///////////////////////////////////////////////////////////////////////////////
public class RIPEMD256 extends BlockHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // rotate int x left n bits.
    private static int RL(int x, int n)
    {
        return (x << n) | (x >>> (32 - n));
    }
    // f1,f2,f3,f4 are the basic RIPEMD128 functions.
    // F
    private static int f1(int x, int y, int z)
    {
        return x ^ y ^ z;
    }
    // G
    private static int f2(int x, int y, int z)
    {
        return (x & y) | (~x & z);
    }
    // H
    private static int f3(int x, int y, int z)
    {
        return (x | ~y) ^ z;
    }
    // I
    private static int f4(int x, int y, int z)
    {
        return (x & z) | (y & ~z);
    }
    private static int F1(int a, int b, int c, int d, int x, int s)
    {
        return RL(a + f1(b, c, d) + x, s);
    }
    private static int F2(int a, int b, int c, int d, int x, int s)
    {
        return RL(a + f2(b, c, d) + x + 0x5a827999, s);
    }
    private static int F3(int a, int b, int c, int d, int x, int s)
    {
        return RL(a + f3(b, c, d) + x + 0x6ed9eba1, s);
    }
    private static int F4(int a, int b, int c, int d, int x, int s)
    {
        return RL(a + f4(b, c, d) + x + 0x8f1bbcdc, s);
    }
    private static int FF1(int a, int b, int c, int d, int x, int s)
    {
        return RL(a + f1(b, c, d) + x, s);
    }
    private static int FF2(int a, int b, int c, int d, int x, int s)
    {
      return RL(a + f2(b, c, d) + x + 0x6d703ef3, s);
    }
    private static int FF3(int a, int b, int c, int d, int x, int s)
    {
      return RL(a + f3(b, c, d) + x + 0x5c4dd124, s);
    }
    private static int FF4(int a, int b, int c, int d, int x, int s)
    {
      return RL(a + f4(b, c, d) + x + 0x50a28be6, s);
    }
    private long byteCount; private int H0, H1, H2, H3, H4, H5, H6, H7;

    // размер хэш-значения в байтах
	@Override public int hashSize() { return 32; }  
	
	// размер блока в байтах
	@Override public int blockSize() { return 64; } 

	// инициализировать алгоритм
	@Override public void init() throws IOException
    { 
        super.init(); byteCount = 0; 

        H0 = 0x67452301; H1 = 0xefcdab89;
        H2 = 0x98badcfe; H3 = 0x10325476; 
        H4 = 0x76543210; H5 = 0xFEDCBA98; 
        H6 = 0x89ABCDEF; H7 = 0x01234567;
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
        int a  = H0; int b  = H1; int c  = H2; int d  = H3;
        int aa = H4; int bb = H5; int cc = H6; int dd = H7; int t; 
        //
        // Round 1
        //
        a = F1(a, b, c, d, X[ 0], 11);
        d = F1(d, a, b, c, X[ 1], 14);
        c = F1(c, d, a, b, X[ 2], 15);
        b = F1(b, c, d, a, X[ 3], 12);
        a = F1(a, b, c, d, X[ 4],  5);
        d = F1(d, a, b, c, X[ 5],  8);
        c = F1(c, d, a, b, X[ 6],  7);
        b = F1(b, c, d, a, X[ 7],  9);
        a = F1(a, b, c, d, X[ 8], 11);
        d = F1(d, a, b, c, X[ 9], 13);
        c = F1(c, d, a, b, X[10], 14);
        b = F1(b, c, d, a, X[11], 15);
        a = F1(a, b, c, d, X[12],  6);
        d = F1(d, a, b, c, X[13],  7);
        c = F1(c, d, a, b, X[14],  9);
        b = F1(b, c, d, a, X[15],  8);

        aa = FF4(aa, bb, cc, dd, X[ 5],  8);
        dd = FF4(dd, aa, bb, cc, X[14],  9);
        cc = FF4(cc, dd, aa, bb, X[ 7],  9);
        bb = FF4(bb, cc, dd, aa, X[ 0], 11);
        aa = FF4(aa, bb, cc, dd, X[ 9], 13);
        dd = FF4(dd, aa, bb, cc, X[ 2], 15);
        cc = FF4(cc, dd, aa, bb, X[11], 15);
        bb = FF4(bb, cc, dd, aa, X[ 4],  5);
        aa = FF4(aa, bb, cc, dd, X[13],  7);
        dd = FF4(dd, aa, bb, cc, X[ 6],  7);
        cc = FF4(cc, dd, aa, bb, X[15],  8);
        bb = FF4(bb, cc, dd, aa, X[ 8], 11);
        aa = FF4(aa, bb, cc, dd, X[ 1], 14);
        dd = FF4(dd, aa, bb, cc, X[10], 14);
        cc = FF4(cc, dd, aa, bb, X[ 3], 12);
        bb = FF4(bb, cc, dd, aa, X[12],  6);

        t = a; a = aa; aa = t;
        
        // Round 2
        a = F2(a, b, c, d, X[ 7],  7);
        d = F2(d, a, b, c, X[ 4],  6);
        c = F2(c, d, a, b, X[13],  8);
        b = F2(b, c, d, a, X[ 1], 13);
        a = F2(a, b, c, d, X[10], 11);
        d = F2(d, a, b, c, X[ 6],  9);
        c = F2(c, d, a, b, X[15],  7);
        b = F2(b, c, d, a, X[ 3], 15);
        a = F2(a, b, c, d, X[12],  7);
        d = F2(d, a, b, c, X[ 0], 12);
        c = F2(c, d, a, b, X[ 9], 15);
        b = F2(b, c, d, a, X[ 5],  9);
        a = F2(a, b, c, d, X[ 2], 11);
        d = F2(d, a, b, c, X[14],  7);
        c = F2(c, d, a, b, X[11], 13);
        b = F2(b, c, d, a, X[ 8], 12);

        aa = FF3(aa, bb, cc, dd, X[ 6],  9);
        dd = FF3(dd, aa, bb, cc, X[11], 13);
        cc = FF3(cc, dd, aa, bb, X[ 3], 15);
        bb = FF3(bb, cc, dd, aa, X[ 7],  7);
        aa = FF3(aa, bb, cc, dd, X[ 0], 12);
        dd = FF3(dd, aa, bb, cc, X[13],  8);
        cc = FF3(cc, dd, aa, bb, X[ 5],  9);
        bb = FF3(bb, cc, dd, aa, X[10], 11);
        aa = FF3(aa, bb, cc, dd, X[14],  7);
        dd = FF3(dd, aa, bb, cc, X[15],  7);
        cc = FF3(cc, dd, aa, bb, X[ 8], 12);
        bb = FF3(bb, cc, dd, aa, X[12],  7);
        aa = FF3(aa, bb, cc, dd, X[ 4],  6);
        dd = FF3(dd, aa, bb, cc, X[ 9], 15);
        cc = FF3(cc, dd, aa, bb, X[ 1], 13);
        bb = FF3(bb, cc, dd, aa, X[ 2], 11);

        t = b; b = bb; bb = t;
        
        // Round 3
        a = F3(a, b, c, d, X[ 3], 11);
        d = F3(d, a, b, c, X[10], 13);
        c = F3(c, d, a, b, X[14],  6);
        b = F3(b, c, d, a, X[ 4],  7);
        a = F3(a, b, c, d, X[ 9], 14);
        d = F3(d, a, b, c, X[15],  9);
        c = F3(c, d, a, b, X[ 8], 13);
        b = F3(b, c, d, a, X[ 1], 15);
        a = F3(a, b, c, d, X[ 2], 14);
        d = F3(d, a, b, c, X[ 7],  8);
        c = F3(c, d, a, b, X[ 0], 13);
        b = F3(b, c, d, a, X[ 6],  6);
        a = F3(a, b, c, d, X[13],  5);
        d = F3(d, a, b, c, X[11], 12);
        c = F3(c, d, a, b, X[ 5],  7);
        b = F3(b, c, d, a, X[12],  5);

        aa = FF2(aa, bb, cc, dd, X[15],  9);
        dd = FF2(dd, aa, bb, cc, X[ 5],  7);
        cc = FF2(cc, dd, aa, bb, X[ 1], 15);
        bb = FF2(bb, cc, dd, aa, X[ 3], 11);
        aa = FF2(aa, bb, cc, dd, X[ 7],  8);
        dd = FF2(dd, aa, bb, cc, X[14],  6);
        cc = FF2(cc, dd, aa, bb, X[ 6],  6);
        bb = FF2(bb, cc, dd, aa, X[ 9], 14);
        aa = FF2(aa, bb, cc, dd, X[11], 12);
        dd = FF2(dd, aa, bb, cc, X[ 8], 13);
        cc = FF2(cc, dd, aa, bb, X[12],  5);
        bb = FF2(bb, cc, dd, aa, X[ 2], 14);
        aa = FF2(aa, bb, cc, dd, X[10], 13);
        dd = FF2(dd, aa, bb, cc, X[ 0], 13);
        cc = FF2(cc, dd, aa, bb, X[ 4],  7);
        bb = FF2(bb, cc, dd, aa, X[13],  5);

        t = c; c = cc; cc = t;

        // Round 4
        a = F4(a, b, c, d, X[ 1], 11);
        d = F4(d, a, b, c, X[ 9], 12);
        c = F4(c, d, a, b, X[11], 14);
        b = F4(b, c, d, a, X[10], 15);
        a = F4(a, b, c, d, X[ 0], 14);
        d = F4(d, a, b, c, X[ 8], 15);
        c = F4(c, d, a, b, X[12],  9);
        b = F4(b, c, d, a, X[ 4],  8);
        a = F4(a, b, c, d, X[13],  9);
        d = F4(d, a, b, c, X[ 3], 14);
        c = F4(c, d, a, b, X[ 7],  5);
        b = F4(b, c, d, a, X[15],  6);
        a = F4(a, b, c, d, X[14],  8);
        d = F4(d, a, b, c, X[ 5],  6);
        c = F4(c, d, a, b, X[ 6],  5);
        b = F4(b, c, d, a, X[ 2], 12);

        aa = FF1(aa, bb, cc, dd, X[ 8], 15);
        dd = FF1(dd, aa, bb, cc, X[ 6],  5);
        cc = FF1(cc, dd, aa, bb, X[ 4],  8);
        bb = FF1(bb, cc, dd, aa, X[ 1], 11);
        aa = FF1(aa, bb, cc, dd, X[ 3], 14);
        dd = FF1(dd, aa, bb, cc, X[11], 14);
        cc = FF1(cc, dd, aa, bb, X[15],  6);
        bb = FF1(bb, cc, dd, aa, X[ 0], 14);
        aa = FF1(aa, bb, cc, dd, X[ 5],  6);
        dd = FF1(dd, aa, bb, cc, X[12],  9);
        cc = FF1(cc, dd, aa, bb, X[ 2], 12);
        bb = FF1(bb, cc, dd, aa, X[13],  9);
        aa = FF1(aa, bb, cc, dd, X[ 9], 12);
        dd = FF1(dd, aa, bb, cc, X[ 7],  5);
        cc = FF1(cc, dd, aa, bb, X[10], 15);
        bb = FF1(bb, cc, dd, aa, X[14],  8);

        t = d; d = dd; dd = t;

        H0 +=  a; H1 +=  b; H2 +=  c; H3 +=  d;
        H4 += aa; H5 += bb; H6 += cc; H7 += dd;
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
        Convert.fromInt32(H0, ENDIAN, buf, bufOff +  0); 
        Convert.fromInt32(H1, ENDIAN, buf, bufOff +  4); 
        Convert.fromInt32(H2, ENDIAN, buf, bufOff +  8); 
        Convert.fromInt32(H3, ENDIAN, buf, bufOff + 12); 
        Convert.fromInt32(H4, ENDIAN, buf, bufOff + 16); 
        Convert.fromInt32(H5, ENDIAN, buf, bufOff + 20); 
        Convert.fromInt32(H6, ENDIAN, buf, bufOff + 24); 
        Convert.fromInt32(H7, ENDIAN, buf, bufOff + 28); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Hash hashAlgorithm) throws Exception
    {
        knownTest(hashAlgorithm, 1, 
            "", new byte[] { 
            (byte)0x02, (byte)0xba, (byte)0x4c, (byte)0x4e, 
            (byte)0x5f, (byte)0x8e, (byte)0xcd, (byte)0x18, 
            (byte)0x77, (byte)0xfc, (byte)0x52, (byte)0xd6, 
            (byte)0x4d, (byte)0x30, (byte)0xe3, (byte)0x7a, 
            (byte)0x2d, (byte)0x97, (byte)0x74, (byte)0xfb, 
            (byte)0x1e, (byte)0x5d, (byte)0x02, (byte)0x63, 
            (byte)0x80, (byte)0xae, (byte)0x01, (byte)0x68, 
            (byte)0xe3, (byte)0xc5, (byte)0x52, (byte)0x2d
        }); 
        knownTest(hashAlgorithm, 1, 
            "a", new byte[] { 
            (byte)0xf9, (byte)0x33, (byte)0x3e, (byte)0x45, 
            (byte)0xd8, (byte)0x57, (byte)0xf5, (byte)0xd9, 
            (byte)0x0a, (byte)0x91, (byte)0xba, (byte)0xb7, 
            (byte)0x0a, (byte)0x1e, (byte)0xba, (byte)0x0c, 
            (byte)0xfb, (byte)0x1b, (byte)0xe4, (byte)0xb0, 
            (byte)0x78, (byte)0x3c, (byte)0x9a, (byte)0xcf, 
            (byte)0xcd, (byte)0x88, (byte)0x3a, (byte)0x91, 
            (byte)0x34, (byte)0x69, (byte)0x29, (byte)0x25
        }); 
        knownTest(hashAlgorithm, 1, 
            "abc", new byte[] { 
            (byte)0xaf, (byte)0xbd, (byte)0x6e, (byte)0x22, 
            (byte)0x8b, (byte)0x9d, (byte)0x8c, (byte)0xbb, 
            (byte)0xce, (byte)0xf5, (byte)0xca, (byte)0x2d, 
            (byte)0x03, (byte)0xe6, (byte)0xdb, (byte)0xa1, 
            (byte)0x0a, (byte)0xc0, (byte)0xbc, (byte)0x7d, 
            (byte)0xcb, (byte)0xe4, (byte)0x68, (byte)0x0e, 
            (byte)0x1e, (byte)0x42, (byte)0xd2, (byte)0xe9, 
            (byte)0x75, (byte)0x45, (byte)0x9b, (byte)0x65
        }); 
        knownTest(hashAlgorithm, 1, 
            "message digest", new byte[] { 
            (byte)0x87, (byte)0xe9, (byte)0x71, (byte)0x75, 
            (byte)0x9a, (byte)0x1c, (byte)0xe4, (byte)0x7a, 
            (byte)0x51, (byte)0x4d, (byte)0x5c, (byte)0x91, 
            (byte)0x4c, (byte)0x39, (byte)0x2c, (byte)0x90, 
            (byte)0x18, (byte)0xc7, (byte)0xc4, (byte)0x6b, 
            (byte)0xc1, (byte)0x44, (byte)0x65, (byte)0x55, 
            (byte)0x4a, (byte)0xfc, (byte)0xdf, (byte)0x54, 
            (byte)0xa5, (byte)0x07, (byte)0x0c, (byte)0x0e
        }); 
        knownTest(hashAlgorithm, 1, 
            "abcdefghijklmnopqrstuvwxyz", new byte[] { 
            (byte)0x64, (byte)0x9d, (byte)0x30, (byte)0x34, 
            (byte)0x75, (byte)0x1e, (byte)0xa2, (byte)0x16, 
            (byte)0x77, (byte)0x6b, (byte)0xf9, (byte)0xa1, 
            (byte)0x8a, (byte)0xcc, (byte)0x81, (byte)0xbc, 
            (byte)0x78, (byte)0x96, (byte)0x11, (byte)0x8a, 
            (byte)0x51, (byte)0x97, (byte)0x96, (byte)0x87, 
            (byte)0x82, (byte)0xdd, (byte)0x1f, (byte)0xd9, 
            (byte)0x7d, (byte)0x8d, (byte)0x51, (byte)0x33
        }); 
        knownTest(hashAlgorithm, 1, 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + 
            "abcdefghijklmnopqrstuvwxyz0123456789", new byte[] { 
            (byte)0x57, (byte)0x40, (byte)0xa4, (byte)0x08, 
            (byte)0xac, (byte)0x16, (byte)0xb7, (byte)0x20, 
            (byte)0xb8, (byte)0x44, (byte)0x24, (byte)0xae, 
            (byte)0x93, (byte)0x1c, (byte)0xbb, (byte)0x1f, 
            (byte)0xe3, (byte)0x63, (byte)0xd1, (byte)0xd0, 
            (byte)0xbf, (byte)0x40, (byte)0x17, (byte)0xf1, 
            (byte)0xa8, (byte)0x9f, (byte)0x7e, (byte)0xa6, 
            (byte)0xde, (byte)0x77, (byte)0xa0, (byte)0xb8
        }); 
        knownTest(hashAlgorithm, 1, 
            "1234567890123456789012345678901234567890" + 
            "1234567890123456789012345678901234567890", new byte[] { 
            (byte)0x06, (byte)0xfd, (byte)0xcc, (byte)0x7a, 
            (byte)0x40, (byte)0x95, (byte)0x48, (byte)0xaa, 
            (byte)0xf9, (byte)0x13, (byte)0x68, (byte)0xc0, 
            (byte)0x6a, (byte)0x62, (byte)0x75, (byte)0xb5, 
            (byte)0x53, (byte)0xe3, (byte)0xf0, (byte)0x99, 
            (byte)0xbf, (byte)0x0e, (byte)0xa4, (byte)0xed, 
            (byte)0xfd, (byte)0x67, (byte)0x78, (byte)0xdf, 
            (byte)0x89, (byte)0xa8, (byte)0x90, (byte)0xdd
        }); 
    }
}
