package aladdin.capi.ansi.hash;
import aladdin.math.*;
import aladdin.capi.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования SHA224
///////////////////////////////////////////////////////////////////////////////
public class SHA2_224 extends BlockHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 

    // SHA-224 Constants
    // (represent the first 32 bits of the fractional parts of the
    // cube roots of the first sixty-four prime numbers)
    //
    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    // SHA-224 functions 
    private static int Ch(int x, int y, int z)
    {
        return ((x & y) ^ ((~x) & z));
    }

    private static int Maj(int x, int y, int z)
    {
        return ((x & y) ^ (x & z) ^ (y & z));
    }

    private static int Sum0(int x)
    {
        return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^ ((x >>> 22) | (x << 10));
    }

    private static int Sum1(int x)
    {
        return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^ ((x >>> 25) | (x << 7));
    }

    private static int Theta0(int x)
    {
        return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    }

    private static int Theta1(int x)
    {
        return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
    }
    private long byteCount; private int H1, H2, H3, H4, H5, H6, H7, H8;

    // размер хэш-значения в байтах
	@Override public int hashSize() { return 28; }  
	
	// размер блока в байтах
	@Override public int blockSize() { return 64; } 

	// инициализировать алгоритм
	@Override public void init() throws IOException
    { 
        super.init(); byteCount = 0;  

        H1 = 0xc1059ed8; H2 = 0x367cd507;
        H3 = 0x3070dd17; H4 = 0xf70e5939;
        H5 = 0xffc00b31; H6 = 0x68581511;
        H7 = 0x64f98fa7; H8 = 0xbefa4fa4;
    }
	// обработать блок данных
	@Override protected void update(byte[] data, int dataOff)  
    {
        // выделить буфер требуемого размера
        int[] X = new int[64]; byteCount += blockSize();
        
        // скопировать данные в буфер
        for (int i = 0; i < 16; i++)
        {
            // скопировать данные в буфер
            X[i] = Convert.toInt32(data, dataOff + 4 * i, ENDIAN); 
        }
        //
        // expand 16 word block into 64 word blocks.
        //
        for (int t = 16; t <= 63; t++)
        {
            X[t] = Theta1(X[t - 2]) + X[t - 7] + Theta0(X[t - 15]) + X[t - 16];
        }
        //
        // set up working variables.
        //
        int a = H1; int b = H2; int c = H3; int d = H4;
        int e = H5; int f = H6; int g = H7; int h = H8;

        for(int i = 0, t = 0; i < 8; i ++)
        {
            // t = 8 * i
            h += Sum1(e) + Ch(e, f, g) + K[t] + X[t];
            d += h;
            h += Sum0(a) + Maj(a, b, c);
            ++t;

            // t = 8 * i + 1
            g += Sum1(d) + Ch(d, e, f) + K[t] + X[t];
            c += g;
            g += Sum0(h) + Maj(h, a, b);
            ++t;

            // t = 8 * i + 2
            f += Sum1(c) + Ch(c, d, e) + K[t] + X[t];
            b += f;
            f += Sum0(g) + Maj(g, h, a);
            ++t;

            // t = 8 * i + 3
            e += Sum1(b) + Ch(b, c, d) + K[t] + X[t];
            a += e;
            e += Sum0(f) + Maj(f, g, h);
            ++t;

            // t = 8 * i + 4
            d += Sum1(a) + Ch(a, b, c) + K[t] + X[t];
            h += d;
            d += Sum0(e) + Maj(e, f, g);
            ++t;

            // t = 8 * i + 5
            c += Sum1(h) + Ch(h, a, b) + K[t] + X[t];
            g += c;
            c += Sum0(d) + Maj(d, e, f);
            ++t;

            // t = 8 * i + 6
            b += Sum1(g) + Ch(g, h, a) + K[t] + X[t];
            f += b;
            b += Sum0(c) + Maj(c, d, e);
            ++t;

            // t = 8 * i + 7
            a += Sum1(f) + Ch(f, g, h) + K[t] + X[t];
            e += a;
            a += Sum0(b) + Maj(b, c, d);
            ++t;
        }
        H1 += a; H2 += b; H3 += c; H4 += d;
        H5 += e; H6 += f; H7 += g; H8 += h;
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
        Convert.fromInt32(H5, ENDIAN, buf, bufOff + 16); 
        Convert.fromInt32(H6, ENDIAN, buf, bufOff + 20); 
        Convert.fromInt32(H7, ENDIAN, buf, bufOff + 24); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Hash hashAlgorithm) throws Exception
    {
        knownTest(hashAlgorithm, 1, 
            "abc", new byte[] {
            (byte)0x23, (byte)0x09, (byte)0x7D, (byte)0x22, 
            (byte)0x34, (byte)0x05, (byte)0xD8, (byte)0x22, 
            (byte)0x86, (byte)0x42, (byte)0xA4, (byte)0x77, 
            (byte)0xBD, (byte)0xA2, (byte)0x55, (byte)0xB3, 
            (byte)0x2A, (byte)0xAD, (byte)0xBC, (byte)0xE4, 
            (byte)0xBD, (byte)0xA0, (byte)0xB3, (byte)0xF7, 
            (byte)0xE3, (byte)0x6C, (byte)0x9D, (byte)0xA7
        }); 
        knownTest(hashAlgorithm, 1, 
            "abcdbcdecdefdefgefghfghighij" + 
            "hijkijkljklmklmnlmnomnopnopq", new byte[] {
            (byte)0x75, (byte)0x38, (byte)0x8B, (byte)0x16, 
            (byte)0x51, (byte)0x27, (byte)0x76, (byte)0xCC, 
            (byte)0x5D, (byte)0xBA, (byte)0x5D, (byte)0xA1, 
            (byte)0xFD, (byte)0x89, (byte)0x01, (byte)0x50, 
            (byte)0xB0, (byte)0xC6, (byte)0x45, (byte)0x5C, 
            (byte)0xB4, (byte)0xF5, (byte)0x8B, (byte)0x19, 
            (byte)0x52, (byte)0x52, (byte)0x25, (byte)0x25
        }); 
        knownTest(hashAlgorithm, 1000000, 
            "a", new byte[] {
            (byte)0x20, (byte)0x79, (byte)0x46, (byte)0x55, 
            (byte)0x98, (byte)0x0C, (byte)0x91, (byte)0xD8, 
            (byte)0xBB, (byte)0xB4, (byte)0xC1, (byte)0xEA, 
            (byte)0x97, (byte)0x61, (byte)0x8A, (byte)0x4B, 
            (byte)0xF0, (byte)0x3F, (byte)0x42, (byte)0x58, 
            (byte)0x19, (byte)0x48, (byte)0xB2, (byte)0xEE, 
            (byte)0x4E, (byte)0xE7, (byte)0xAD, (byte)0x67
        }); 
        knownTest(hashAlgorithm, 10, 
            "01234567012345670123456701234567" + 
            "01234567012345670123456701234567", new byte[] {
            (byte)0x56, (byte)0x7F, (byte)0x69, (byte)0xF1, 
            (byte)0x68, (byte)0xCD, (byte)0x78, (byte)0x44, 
            (byte)0xE6, (byte)0x52, (byte)0x59, (byte)0xCE, 
            (byte)0x65, (byte)0x8F, (byte)0xE7, (byte)0xAA, 
            (byte)0xDF, (byte)0xA2, (byte)0x52, (byte)0x16, 
            (byte)0xE6, (byte)0x8E, (byte)0xCA, (byte)0x0E, 
            (byte)0xB7, (byte)0xAB, (byte)0x82, (byte)0x62
        }); 
        knownTest(hashAlgorithm, 1, 
            new byte[] { 0x07 }, new byte[] {
            (byte)0x00, (byte)0xEC, (byte)0xD5, (byte)0xF1, 
            (byte)0x38, (byte)0x42, (byte)0x2B, (byte)0x8A, 
            (byte)0xD7, (byte)0x4C, (byte)0x97, (byte)0x99, 
            (byte)0xFD, (byte)0x82, (byte)0x6C, (byte)0x53, 
            (byte)0x1B, (byte)0xAD, (byte)0x2F, (byte)0xCA, 
            (byte)0xBC, (byte)0x74, (byte)0x50, (byte)0xBE, 
            (byte)0xE2, (byte)0xAA, (byte)0x8C, (byte)0x2A
        }); 
        knownTest(hashAlgorithm, 1, new byte[] { 
            (byte)0x18, (byte)0x80, (byte)0x40, (byte)0x05, 
            (byte)0xdd, (byte)0x4f, (byte)0xbd, (byte)0x15, 
            (byte)0x56, (byte)0x29, (byte)0x9d, (byte)0x6f, 
            (byte)0x9d, (byte)0x93, (byte)0xdf, (byte)0x62
        }, new byte[] {
            (byte)0xDF, (byte)0x90, (byte)0xD7, (byte)0x8A, 
            (byte)0xA7, (byte)0x88, (byte)0x21, (byte)0xC9, 
            (byte)0x9B, (byte)0x40, (byte)0xBA, (byte)0x4C, 
            (byte)0x96, (byte)0x69, (byte)0x21, (byte)0xAC, 
            (byte)0xCD, (byte)0x8F, (byte)0xFB, (byte)0x1E, 
            (byte)0x98, (byte)0xAC, (byte)0x38, (byte)0x8E, 
            (byte)0x56, (byte)0x19, (byte)0x1D, (byte)0xB1
        }); 
        knownTest(hashAlgorithm, 1, new byte[] { 
            (byte)0x55, (byte)0xb2, (byte)0x10, (byte)0x07, 
            (byte)0x9c, (byte)0x61, (byte)0xb5, (byte)0x3a, 
            (byte)0xdd, (byte)0x52, (byte)0x06, (byte)0x22, 
            (byte)0xd1, (byte)0xac, (byte)0x97, (byte)0xd5,
            (byte)0xcd, (byte)0xbe, (byte)0x8c, (byte)0xb3, 
            (byte)0x3a, (byte)0xa0, (byte)0xae, (byte)0x34, 
            (byte)0x45, (byte)0x17, (byte)0xbe, (byte)0xe4, 
            (byte)0xd7, (byte)0xba, (byte)0x09, (byte)0xab, 
            (byte)0xc8, (byte)0x53, (byte)0x3c, (byte)0x52, 
            (byte)0x50, (byte)0x88, (byte)0x7a, (byte)0x43, 
            (byte)0xbe, (byte)0xbb, (byte)0xac, (byte)0x90, 
            (byte)0x6c, (byte)0x2e, (byte)0x18, (byte)0x37, 
            (byte)0xf2, (byte)0x6b, (byte)0x36, (byte)0xa5, 
            (byte)0x9a, (byte)0xe3, (byte)0xbe, (byte)0x78, 
            (byte)0x14, (byte)0xd5, (byte)0x06, (byte)0x89, 
            (byte)0x6b, (byte)0x71, (byte)0x8b, (byte)0x2a, 
            (byte)0x38, (byte)0x3e, (byte)0xcd, (byte)0xac, 
            (byte)0x16, (byte)0xb9, (byte)0x61, (byte)0x25, 
            (byte)0x55, (byte)0x3f, (byte)0x41, (byte)0x6f, 
            (byte)0xf3, (byte)0x2c, (byte)0x66, (byte)0x74, 
            (byte)0xc7, (byte)0x45, (byte)0x99, (byte)0xa9, 
            (byte)0x00, (byte)0x53, (byte)0x86, (byte)0xd9, 
            (byte)0xce, (byte)0x11, (byte)0x12, (byte)0x24, 
            (byte)0x5f, (byte)0x48, (byte)0xee, (byte)0x47, 
            (byte)0x0d, (byte)0x39, (byte)0x6c, (byte)0x1e, 
            (byte)0xd6, (byte)0x3b, (byte)0x92, (byte)0x67, 
            (byte)0x0c, (byte)0xa5, (byte)0x6e, (byte)0xc8, 
            (byte)0x4d, (byte)0xee, (byte)0xa8, (byte)0x14, 
            (byte)0xb6, (byte)0x13, (byte)0x5e, (byte)0xca, 
            (byte)0x54, (byte)0x39, (byte)0x2b, (byte)0xde, 
            (byte)0xdb, (byte)0x94, (byte)0x89, (byte)0xbc, 
            (byte)0x9b, (byte)0x87, (byte)0x5a, (byte)0x8b, 
            (byte)0xaf, (byte)0x0d, (byte)0xc1, (byte)0xae, 
            (byte)0x78, (byte)0x57, (byte)0x36, (byte)0x91, 
            (byte)0x4a, (byte)0xb7, (byte)0xda, (byte)0xa2, 
            (byte)0x64, (byte)0xbc, (byte)0x07, (byte)0x9d, 
            (byte)0x26, (byte)0x9f, (byte)0x2c, (byte)0x0d, 
            (byte)0x7e, (byte)0xdd, (byte)0xd8, (byte)0x10, 
            (byte)0xa4, (byte)0x26, (byte)0x14, (byte)0x5a, 
            (byte)0x07, (byte)0x76, (byte)0xf6, (byte)0x7c, 
            (byte)0x87, (byte)0x82, (byte)0x73
        }, new byte[] {
            (byte)0x0B, (byte)0x31, (byte)0x89, (byte)0x4E, 
            (byte)0xC8, (byte)0x93, (byte)0x7A, (byte)0xD9, 
            (byte)0xB9, (byte)0x1B, (byte)0xDF, (byte)0xBC, 
            (byte)0xBA, (byte)0x29, (byte)0x4D, (byte)0x9A, 
            (byte)0xDE, (byte)0xFA, (byte)0xA1, (byte)0x8E, 
            (byte)0x09, (byte)0x30, (byte)0x5E, (byte)0x9F, 
            (byte)0x20, (byte)0xD5, (byte)0xC3, (byte)0xA4
        }); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // HMAC
    ////////////////////////////////////////////////////////////////////////////
    public static void testHMAC(Mac algorithm) throws Exception
    {
        int[] keySizes = algorithm.keyFactory().keySizes(); 
        
        if (KeySizes.contains(keySizes, 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
        }, 1, "Hi There", new byte[] {
            (byte)0x89, (byte)0x6f, (byte)0xb1, (byte)0x12, 
            (byte)0x8a, (byte)0xbb, (byte)0xdf, (byte)0x19, 
            (byte)0x68, (byte)0x32, (byte)0x10, (byte)0x7c, 
            (byte)0xd4, (byte)0x9d, (byte)0xf3, (byte)0x3f,
            (byte)0x47, (byte)0xb4, (byte)0xb1, (byte)0x16, 
            (byte)0x99, (byte)0x12, (byte)0xba, (byte)0x4f, 
            (byte)0x53, (byte)0x68, (byte)0x4b, (byte)0x22
        }); 
        if (KeySizes.contains(keySizes, 4))
        Mac.knownTest(algorithm, "Jefe".getBytes("UTF-8"), 
            1, "what do ya want for nothing?", new byte[] {
            (byte)0xa3, (byte)0x0e, (byte)0x01, (byte)0x09, 
            (byte)0x8b, (byte)0xc6, (byte)0xdb, (byte)0xbf, 
            (byte)0x45, (byte)0x69, (byte)0x0f, (byte)0x3a, 
            (byte)0x7e, (byte)0x9e, (byte)0x6d, (byte)0x0f, 
            (byte)0x8b, (byte)0xbe, (byte)0xa2, (byte)0xa3, 
            (byte)0x9e, (byte)0x61, (byte)0x48, (byte)0x00, 
            (byte)0x8f, (byte)0xd0, (byte)0x5e, (byte)0x44        
        }); 
        if (KeySizes.contains(keySizes, 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
        }, 50, new byte[] { (byte)0xDD }, new byte[] {
            (byte)0x7f, (byte)0xb3, (byte)0xcb, (byte)0x35, 
            (byte)0x88, (byte)0xc6, (byte)0xc1, (byte)0xf6, 
            (byte)0xff, (byte)0xa9, (byte)0x69, (byte)0x4d, 
            (byte)0x7d, (byte)0x6a, (byte)0xd2, (byte)0x64,
            (byte)0x93, (byte)0x65, (byte)0xb0, (byte)0xc1, 
            (byte)0xf6, (byte)0x5d, (byte)0x69, (byte)0xd1, 
            (byte)0xec, (byte)0x83, (byte)0x33, (byte)0xea          
        }); 
        if (KeySizes.contains(keySizes, 25))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
            (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
            (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
            (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
            (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
            (byte)0x19
        }, 50, new byte[] { (byte)0xCD }, new byte[] {
            (byte)0x6c, (byte)0x11, (byte)0x50, (byte)0x68, 
            (byte)0x74, (byte)0x01, (byte)0x3c, (byte)0xac, 
            (byte)0x6a, (byte)0x2a, (byte)0xbc, (byte)0x1b, 
            (byte)0xb3, (byte)0x82, (byte)0x62, (byte)0x7c, 
            (byte)0xec, (byte)0x6a, (byte)0x90, (byte)0xd8, 
            (byte)0x6e, (byte)0xfc, (byte)0x01, (byte)0x2d, 
            (byte)0xe7, (byte)0xaf, (byte)0xec, (byte)0x5a
        }); 
        if (KeySizes.contains(keySizes, 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
        }, 1, "Test With Truncation", new byte[] {
            (byte)0x0e, (byte)0x2a, (byte)0xea, (byte)0x68, 
            (byte)0xa9, (byte)0x0c, (byte)0x8d, (byte)0x37, 
            (byte)0xc9, (byte)0x88, (byte)0xbc, (byte)0xdb, 
            (byte)0x9f, (byte)0xca, (byte)0x6f, (byte)0xa8        
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
            (byte)0xaa, (byte)0xaa, (byte)0xaa
        }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
            (byte)0x95, (byte)0xe9, (byte)0xa0, (byte)0xdb, 
            (byte)0x96, (byte)0x20, (byte)0x95, (byte)0xad, 
            (byte)0xae, (byte)0xbe, (byte)0x9b, (byte)0x2d, 
            (byte)0x6f, (byte)0x0d, (byte)0xbc, (byte)0xe2, 
            (byte)0xd4, (byte)0x99, (byte)0xf1, (byte)0x12, 
            (byte)0xf2, (byte)0xd2, (byte)0xb7, (byte)0x27, 
            (byte)0x3f, (byte)0xa6, (byte)0x87, (byte)0x0e
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
            (byte)0xaa, (byte)0xaa, (byte)0xaa
        }, 1, "This is a test using a larger than block-size key and "      + 
              "a larger than block-size data. The key needs to be hashed "  + 
              "before being used by the HMAC algorithm.", new byte[] {
            (byte)0x3a, (byte)0x85, (byte)0x41, (byte)0x66, 
            (byte)0xac, (byte)0x5d, (byte)0x9f, (byte)0x02, 
            (byte)0x3f, (byte)0x54, (byte)0xd5, (byte)0x17, 
            (byte)0xd0, (byte)0xb3, (byte)0x9d, (byte)0xbd, 
            (byte)0x94, (byte)0x67, (byte)0x70, (byte)0xdb, 
            (byte)0x9c, (byte)0x2b, (byte)0x95, (byte)0xc9, 
            (byte)0xf6, (byte)0xf5, (byte)0x65, (byte)0xd1
        }); 
    }
}
