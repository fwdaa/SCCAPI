package aladdin.capi.ansi.hash;
import aladdin.math.*;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования SHA384
///////////////////////////////////////////////////////////////////////////////
public class SHA2_384 extends BlockHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // SHA-384 and SHA-512 Constants
    // (represent the first 64 bits of the fractional parts of the
    // cube roots of the first sixty-four prime numbers)
    //
    private static final long[] K = {
        0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
        0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
        0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
        0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
        0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
        0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
        0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
        0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
        0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
        0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
        0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
        0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
        0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
        0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
        0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
        0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
        0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
        0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
        0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
        0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };
    // SHA-384 and SHA-512 functions (as for SHA-256 but for longs) */
    private static long Ch(long x, long y, long z)
    {
        return ((x & y) ^ ((~x) & z));
    }
    private static long Maj(long x, long y, long z)
    {
        return ((x & y) ^ (x & z) ^ (y & z));
    }
    private static long Sum0(long x)
    {
        return ((x << 36)|(x >>> 28)) ^ ((x << 30)|(x >>> 34)) ^ ((x << 25)|(x >>> 39));
    }
    private static long Sum1(long x)
    {
        return ((x << 50)|(x >>> 14)) ^ ((x << 46)|(x >>> 18)) ^ ((x << 23)|(x >>> 41));
    }
    private static long Sigma0(long x)
    {
        return ((x << 63)|(x >>> 1)) ^ ((x << 56)|(x >>> 8)) ^ (x >>> 7);
    }
    private static long Sigma1(long x)
    {
        return ((x << 45)|(x >>> 19)) ^ ((x << 3)|(x >>> 61)) ^ (x >>> 6);
    }
    private long byteCount1; private long byteCount2;
    
    private long H1, H2, H3, H4, H5, H6, H7, H8;

    // размер хэш-значения в байтах
	@Override public int hashSize() { return 48; }  
	
	// размер блока в байтах
	@Override public int blockSize() { return 128; } 

	// инициализировать алгоритм
	@Override public void init() throws IOException
    { 
        super.init(); byteCount1 = 0; byteCount2 = 0;  

        // SHA-384 initial hash value
        // The first 64 bits of the fractional parts of the square roots
        // of the 9th through 16th prime numbers
        H1 = 0xcbbb9d5dc1059ed8L; H2 = 0x629a292a367cd507L;
        H3 = 0x9159015a3070dd17L; H4 = 0x152fecd8f70e5939L;
        H5 = 0x67332667ffc00b31L; H6 = 0x8eb44a8768581511L;
        H7 = 0xdb0c2e0d64f98fa7L; H8 = 0x47b5481dbefa4fa4L;
    }
	// обработать блок данных
	@Override protected void update(byte[] data, int dataOff)  
    {
        // выделить буфер требуемого размера
        long[] W = new long[80]; byteCount1 += blockSize();
        
        // учесть возможность переноса
        if (byteCount1 == 0) byteCount2++;  

        // скопировать данные в буфер
        for (int i = 0; i < 16; i++)
        {
            // скопировать данные в буфер
            W[i] = Convert.toInt64(data, dataOff + 8 * i, ENDIAN); 
        }
        //
        // expand 16 word block into 80 word blocks.
        //
        for (int t = 16; t <= 79; t++)
        {
            W[t] = Sigma1(W[t - 2]) + W[t - 7] + Sigma0(W[t - 15]) + W[t - 16];
        }
        //
        // set up working variables.
        //
        long a = H1; long b = H2; long c = H3; long d = H4;
        long e = H5; long f = H6; long g = H7; long h = H8;

        for(int i = 0, t = 0; i < 10; i ++)
        {
          // t = 8 * i
          h += Sum1(e) + Ch(e, f, g) + K[t] + W[t++];
          d += h;
          h += Sum0(a) + Maj(a, b, c);

          // t = 8 * i + 1
          g += Sum1(d) + Ch(d, e, f) + K[t] + W[t++];
          c += g;
          g += Sum0(h) + Maj(h, a, b);

          // t = 8 * i + 2
          f += Sum1(c) + Ch(c, d, e) + K[t] + W[t++];
          b += f;
          f += Sum0(g) + Maj(g, h, a);

          // t = 8 * i + 3
          e += Sum1(b) + Ch(b, c, d) + K[t] + W[t++];
          a += e;
          e += Sum0(f) + Maj(f, g, h);

          // t = 8 * i + 4
          d += Sum1(a) + Ch(a, b, c) + K[t] + W[t++];
          h += d;
          d += Sum0(e) + Maj(e, f, g);

          // t = 8 * i + 5
          c += Sum1(h) + Ch(h, a, b) + K[t] + W[t++];
          g += c;
          c += Sum0(d) + Maj(d, e, f);

          // t = 8 * i + 6
          b += Sum1(g) + Ch(g, h, a) + K[t] + W[t++];
          f += b;
          b += Sum0(c) + Maj(c, d, e);

          // t = 8 * i + 7
          a += Sum1(f) + Ch(f, g, h) + K[t] + W[t++];
          e += a;
          a += Sum0(b) + Maj(b, c, d);
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
        // увеличить размер данных
        byteCount1 += dataLen; long loCount = byteCount1 << 3;  
        
        // определить размер данных в битах
        long hiCount = (byteCount2 << 3) | (byteCount1 >>> 61); 
        
        // выделить буфер для дополнения
        byte[] buffer = new byte[blockSize]; buffer[dataLen] = (byte)0x80;
        
        // скопировать данные
        System.arraycopy(data, dataOff, buffer, 0, dataLen);

        // обработать дополненный блок
        if (dataLen >= 112) { update(buffer, 0);

            // обнулить обработанный блок
            for (int i = 0; i < 112; i++) buffer[i] = 0; 
        }
        // обработать размер 
        Convert.fromInt64(hiCount, ENDIAN, buffer, 112); 
        Convert.fromInt64(loCount, ENDIAN, buffer, 120); update(buffer, 0);
        
        // извлечь хэш-значение
        Convert.fromInt64(H1, ENDIAN, buf, bufOff +  0); 
        Convert.fromInt64(H2, ENDIAN, buf, bufOff +  8); 
        Convert.fromInt64(H3, ENDIAN, buf, bufOff + 16); 
        Convert.fromInt64(H4, ENDIAN, buf, bufOff + 24); 
        Convert.fromInt64(H5, ENDIAN, buf, bufOff + 32); 
        Convert.fromInt64(H6, ENDIAN, buf, bufOff + 40); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Hash hashAlgorithm) throws Exception
    {
        knownTest(hashAlgorithm, 1, 
            "abc", new byte[] {
            (byte)0xCB, (byte)0x00, (byte)0x75, (byte)0x3F, 
            (byte)0x45, (byte)0xA3, (byte)0x5E, (byte)0x8B, 
            (byte)0xB5, (byte)0xA0, (byte)0x3D, (byte)0x69, 
            (byte)0x9A, (byte)0xC6, (byte)0x50, (byte)0x07, 
            (byte)0x27, (byte)0x2C, (byte)0x32, (byte)0xAB, 
            (byte)0x0E, (byte)0xDE, (byte)0xD1, (byte)0x63, 
            (byte)0x1A, (byte)0x8B, (byte)0x60, (byte)0x5A, 
            (byte)0x43, (byte)0xFF, (byte)0x5B, (byte)0xED, 
            (byte)0x80, (byte)0x86, (byte)0x07, (byte)0x2B, 
            (byte)0xA1, (byte)0xE7, (byte)0xCC, (byte)0x23, 
            (byte)0x58, (byte)0xBA, (byte)0xEC, (byte)0xA1, 
            (byte)0x34, (byte)0xC8, (byte)0x25, (byte)0xA7
        }); 
        knownTest(hashAlgorithm, 1, 
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" + 
            "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", new byte[] {
            (byte)0x09, (byte)0x33, (byte)0x0C, (byte)0x33, 
            (byte)0xF7, (byte)0x11, (byte)0x47, (byte)0xE8, 
            (byte)0x3D, (byte)0x19, (byte)0x2F, (byte)0xC7, 
            (byte)0x82, (byte)0xCD, (byte)0x1B, (byte)0x47, 
            (byte)0x53, (byte)0x11, (byte)0x1B, (byte)0x17, 
            (byte)0x3B, (byte)0x3B, (byte)0x05, (byte)0xD2, 
            (byte)0x2F, (byte)0xA0, (byte)0x80, (byte)0x86, 
            (byte)0xE3, (byte)0xB0, (byte)0xF7, (byte)0x12, 
            (byte)0xFC, (byte)0xC7, (byte)0xC7, (byte)0x1A, 
            (byte)0x55, (byte)0x7E, (byte)0x2D, (byte)0xB9, 
            (byte)0x66, (byte)0xC3, (byte)0xE9, (byte)0xFA, 
            (byte)0x91, (byte)0x74, (byte)0x60, (byte)0x39
        }); 
        knownTest(hashAlgorithm, 1000000, 
            "a", new byte[] {
            (byte)0x9D, (byte)0x0E, (byte)0x18, (byte)0x09, 
            (byte)0x71, (byte)0x64, (byte)0x74, (byte)0xCB, 
            (byte)0x08, (byte)0x6E, (byte)0x83, (byte)0x4E, 
            (byte)0x31, (byte)0x0A, (byte)0x4A, (byte)0x1C, 
            (byte)0xED, (byte)0x14, (byte)0x9E, (byte)0x9C, 
            (byte)0x00, (byte)0xF2, (byte)0x48, (byte)0x52, 
            (byte)0x79, (byte)0x72, (byte)0xCE, (byte)0xC5, 
            (byte)0x70, (byte)0x4C, (byte)0x2A, (byte)0x5B, 
            (byte)0x07, (byte)0xB8, (byte)0xB3, (byte)0xDC, 
            (byte)0x38, (byte)0xEC, (byte)0xC4, (byte)0xEB, 
            (byte)0xAE, (byte)0x97, (byte)0xDD, (byte)0xD8, 
            (byte)0x7F, (byte)0x3D, (byte)0x89, (byte)0x85        
        }); 
        knownTest(hashAlgorithm, 10, 
            "01234567012345670123456701234567" + 
            "01234567012345670123456701234567", new byte[] {
            (byte)0x2F, (byte)0xC6, (byte)0x4A, (byte)0x4F, 
            (byte)0x50, (byte)0x0D, (byte)0xDB, (byte)0x68, 
            (byte)0x28, (byte)0xF6, (byte)0xA3, (byte)0x43, 
            (byte)0x0B, (byte)0x8D, (byte)0xD7, (byte)0x2A, 
            (byte)0x36, (byte)0x8E, (byte)0xB7, (byte)0xF3, 
            (byte)0xA8, (byte)0x32, (byte)0x2A, (byte)0x70, 
            (byte)0xBC, (byte)0x84, (byte)0x27, (byte)0x5B, 
            (byte)0x9C, (byte)0x0B, (byte)0x3A, (byte)0xB0, 
            (byte)0x0D, (byte)0x27, (byte)0xA5, (byte)0xCC, 
            (byte)0x3C, (byte)0x2D, (byte)0x22, (byte)0x4A, 
            (byte)0xA6, (byte)0xB6, (byte)0x1A, (byte)0x0D, 
            (byte)0x79, (byte)0xFB, (byte)0x45, (byte)0x96
        }); 
        knownTest(hashAlgorithm, 1, 
            new byte[] { (byte)0xB9 }, new byte[] {
            (byte)0xBC, (byte)0x80, (byte)0x89, (byte)0xA1, 
            (byte)0x90, (byte)0x07, (byte)0xC0, (byte)0xB1, 
            (byte)0x41, (byte)0x95, (byte)0xF4, (byte)0xEC, 
            (byte)0xC7, (byte)0x40, (byte)0x94, (byte)0xFE, 
            (byte)0xC6, (byte)0x4F, (byte)0x01, (byte)0xF9, 
            (byte)0x09, (byte)0x29, (byte)0x28, (byte)0x2C, 
            (byte)0x2F, (byte)0xB3, (byte)0x92, (byte)0x88, 
            (byte)0x15, (byte)0x78, (byte)0x20, (byte)0x8A, 
            (byte)0xD4, (byte)0x66, (byte)0x82, (byte)0x8B, 
            (byte)0x1C, (byte)0x6C, (byte)0x28, (byte)0x3D, 
            (byte)0x27, (byte)0x22, (byte)0xCF, (byte)0x0A, 
            (byte)0xD1, (byte)0xAB, (byte)0x69, (byte)0x38        
        }); 
        knownTest(hashAlgorithm, 1, new byte[] { 
            (byte)0xa4, (byte)0x1c, (byte)0x49, (byte)0x77, 
            (byte)0x79, (byte)0xc0, (byte)0x37, (byte)0x5f, 
            (byte)0xf1, (byte)0x0a, (byte)0x7f, (byte)0x4e, 
            (byte)0x08, (byte)0x59, (byte)0x17, (byte)0x39
        }, new byte[] {
            (byte)0xC9, (byte)0xA6, (byte)0x84, (byte)0x43, 
            (byte)0xA0, (byte)0x05, (byte)0x81, (byte)0x22, 
            (byte)0x56, (byte)0xB8, (byte)0xEC, (byte)0x76, 
            (byte)0xB0, (byte)0x05, (byte)0x16, (byte)0xF0, 
            (byte)0xDB, (byte)0xB7, (byte)0x4F, (byte)0xAB, 
            (byte)0x26, (byte)0xD6, (byte)0x65, (byte)0x91, 
            (byte)0x3F, (byte)0x19, (byte)0x4B, (byte)0x6F, 
            (byte)0xFB, (byte)0x0E, (byte)0x91, (byte)0xEA, 
            (byte)0x99, (byte)0x67, (byte)0x56, (byte)0x6B, 
            (byte)0x58, (byte)0x10, (byte)0x9C, (byte)0xBC, 
            (byte)0x67, (byte)0x5C, (byte)0xC2, (byte)0x08, 
            (byte)0xE4, (byte)0xC8, (byte)0x23, (byte)0xF7
        }); 
        knownTest(hashAlgorithm, 1, new byte[] { 
            (byte)0x39, (byte)0x96, (byte)0x69, (byte)0xe2, 
            (byte)0x8f, (byte)0x6b, (byte)0x9c, (byte)0x6d, 
            (byte)0xbc, (byte)0xbb, (byte)0x69, (byte)0x12, 
            (byte)0xec, (byte)0x10, (byte)0xff, (byte)0xcf,
            (byte)0x74, (byte)0x79, (byte)0x03, (byte)0x49, 
            (byte)0xb7, (byte)0xdc, (byte)0x8f, (byte)0xbe, 
            (byte)0x4a, (byte)0x8e, (byte)0x7b, (byte)0x3b, 
            (byte)0x56, (byte)0x21, (byte)0xdb, (byte)0x0f,
            (byte)0x3e, (byte)0x7d, (byte)0xc8, (byte)0x7f, 
            (byte)0x82, (byte)0x32, (byte)0x64, (byte)0xbb, 
            (byte)0xe4, (byte)0x0d, (byte)0x18, (byte)0x11, 
            (byte)0xc9, (byte)0xea, (byte)0x20, (byte)0x61,
            (byte)0xe1, (byte)0xc8, (byte)0x4a, (byte)0xd1, 
            (byte)0x0a, (byte)0x23, (byte)0xfa, (byte)0xc1, 
            (byte)0x72, (byte)0x7e, (byte)0x72, (byte)0x02, 
            (byte)0xfc, (byte)0x3f, (byte)0x50, (byte)0x42,
            (byte)0xe6, (byte)0xbf, (byte)0x58, (byte)0xcb, 
            (byte)0xa8, (byte)0xa2, (byte)0x74, (byte)0x6e, 
            (byte)0x1f, (byte)0x64, (byte)0xf9, (byte)0xb9, 
            (byte)0xea, (byte)0x35, (byte)0x2c, (byte)0x71,
            (byte)0x15, (byte)0x07, (byte)0x05, (byte)0x3c, 
            (byte)0xf4, (byte)0xe5, (byte)0x33, (byte)0x9d, 
            (byte)0x52, (byte)0x86, (byte)0x5f, (byte)0x25, 
            (byte)0xcc, (byte)0x22, (byte)0xb5, (byte)0xe8,
            (byte)0x77, (byte)0x84, (byte)0xa1, (byte)0x2f, 
            (byte)0xc9, (byte)0x61, (byte)0xd6, (byte)0x6c, 
            (byte)0xb6, (byte)0xe8, (byte)0x95, (byte)0x73, 
            (byte)0x19, (byte)0x9a, (byte)0x2c, (byte)0xe6,
            (byte)0x56, (byte)0x5c, (byte)0xbd, (byte)0xf1, 
            (byte)0x3d, (byte)0xca, (byte)0x40, (byte)0x38, 
            (byte)0x32, (byte)0xcf, (byte)0xcb, (byte)0x0e, 
            (byte)0x8b, (byte)0x72, (byte)0x11, (byte)0xe8,
            (byte)0x3a, (byte)0xf3, (byte)0x2a, (byte)0x11, 
            (byte)0xac, (byte)0x17, (byte)0x92, (byte)0x9f, 
            (byte)0xf1, (byte)0xc0, (byte)0x73, (byte)0xa5, 
            (byte)0x1c, (byte)0xc0, (byte)0x27, (byte)0xaa,
            (byte)0xed, (byte)0xef, (byte)0xf8, (byte)0x5a, 
            (byte)0xad, (byte)0x7c, (byte)0x2b, (byte)0x7c, 
            (byte)0x5a, (byte)0x80, (byte)0x3e, (byte)0x24, 
            (byte)0x04, (byte)0xd9, (byte)0x6d, (byte)0x2a,
            (byte)0x77, (byte)0x35, (byte)0x7b, (byte)0xda, 
            (byte)0x1a, (byte)0x6d, (byte)0xae, (byte)0xed, 
            (byte)0x17, (byte)0x15, (byte)0x1c, (byte)0xb9, 
            (byte)0xbc, (byte)0x51, (byte)0x25, (byte)0xa4,
            (byte)0x22, (byte)0xe9, (byte)0x41, (byte)0xde, 
            (byte)0x0c, (byte)0xa0, (byte)0xfc, (byte)0x50, 
            (byte)0x11, (byte)0xc2, (byte)0x3e, (byte)0xcf, 
            (byte)0xfe, (byte)0xfd, (byte)0xd0, (byte)0x96,
            (byte)0x76, (byte)0x71, (byte)0x1c, (byte)0xf3, 
            (byte)0xdb, (byte)0x0a, (byte)0x34, (byte)0x40, 
            (byte)0x72, (byte)0x0e, (byte)0x16, (byte)0x15, 
            (byte)0xc1, (byte)0xf2, (byte)0x2f, (byte)0xbc,
            (byte)0x3c, (byte)0x72, (byte)0x1d, (byte)0xe5, 
            (byte)0x21, (byte)0xe1, (byte)0xb9, (byte)0x9b, 
            (byte)0xa1, (byte)0xbd, (byte)0x55, (byte)0x77, 
            (byte)0x40, (byte)0x86, (byte)0x42, (byte)0x14, 
            (byte)0x7e, (byte)0xd0, (byte)0x96
        }, new byte[] {
            (byte)0x4F, (byte)0x44, (byte)0x0D, (byte)0xB1, 
            (byte)0xE6, (byte)0xED, (byte)0xD2, (byte)0x89, 
            (byte)0x9F, (byte)0xA3, (byte)0x35, (byte)0xF0, 
            (byte)0x95, (byte)0x15, (byte)0xAA, (byte)0x02, 
            (byte)0x5E, (byte)0xE1, (byte)0x77, (byte)0xA7, 
            (byte)0x9F, (byte)0x4B, (byte)0x4A, (byte)0xAF, 
            (byte)0x38, (byte)0xE4, (byte)0x2B, (byte)0x5C, 
            (byte)0x4D, (byte)0xE6, (byte)0x60, (byte)0xF5, 
            (byte)0xDE, (byte)0x8F, (byte)0xB2, (byte)0xA5, 
            (byte)0xB2, (byte)0xFB, (byte)0xD2, (byte)0xA3, 
            (byte)0xCB, (byte)0xFF, (byte)0xD2, (byte)0x0C, 
            (byte)0xFF, (byte)0x12, (byte)0x88, (byte)0xC0        
        }); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // HMAC
    ////////////////////////////////////////////////////////////////////////////
    public static void testHMAC(Mac algorithm) throws Exception
    {
        if (KeySizes.contains(algorithm.keySizes(), 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
        }, 1, "Hi There", new byte[] {
            (byte)0xaf, (byte)0xd0, (byte)0x39, (byte)0x44, 
            (byte)0xd8, (byte)0x48, (byte)0x95, (byte)0x62, 
            (byte)0x6b, (byte)0x08, (byte)0x25, (byte)0xf4, 
            (byte)0xab, (byte)0x46, (byte)0x90, (byte)0x7f, 
            (byte)0x15, (byte)0xf9, (byte)0xda, (byte)0xdb, 
            (byte)0xe4, (byte)0x10, (byte)0x1e, (byte)0xc6, 
            (byte)0x82, (byte)0xaa, (byte)0x03, (byte)0x4c, 
            (byte)0x7c, (byte)0xeb, (byte)0xc5, (byte)0x9c, 
            (byte)0xfa, (byte)0xea, (byte)0x9e, (byte)0xa9, 
            (byte)0x07, (byte)0x6e, (byte)0xde, (byte)0x7f, 
            (byte)0x4a, (byte)0xf1, (byte)0x52, (byte)0xe8, 
            (byte)0xb2, (byte)0xfa, (byte)0x9c, (byte)0xb6
        }); 
        if (KeySizes.contains(algorithm.keySizes(), 4))
        Mac.knownTest(algorithm, "Jefe".getBytes("UTF-8"), 
            1, "what do ya want for nothing?", new byte[] {
            (byte)0xaf, (byte)0x45, (byte)0xd2, (byte)0xe3, 
            (byte)0x76, (byte)0x48, (byte)0x40, (byte)0x31, 
            (byte)0x61, (byte)0x7f, (byte)0x78, (byte)0xd2, 
            (byte)0xb5, (byte)0x8a, (byte)0x6b, (byte)0x1b, 
            (byte)0x9c, (byte)0x7e, (byte)0xf4, (byte)0x64, 
            (byte)0xf5, (byte)0xa0, (byte)0x1b, (byte)0x47, 
            (byte)0xe4, (byte)0x2e, (byte)0xc3, (byte)0x73, 
            (byte)0x63, (byte)0x22, (byte)0x44, (byte)0x5e, 
            (byte)0x8e, (byte)0x22, (byte)0x40, (byte)0xca, 
            (byte)0x5e, (byte)0x69, (byte)0xe2, (byte)0xc7, 
            (byte)0x8b, (byte)0x32, (byte)0x39, (byte)0xec, 
            (byte)0xfa, (byte)0xb2, (byte)0x16, (byte)0x49
        }); 
        if (KeySizes.contains(algorithm.keySizes(), 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
        }, 50, new byte[] { (byte)0xDD }, new byte[] {
            (byte)0x88, (byte)0x06, (byte)0x26, (byte)0x08, 
            (byte)0xd3, (byte)0xe6, (byte)0xad, (byte)0x8a, 
            (byte)0x0a, (byte)0xa2, (byte)0xac, (byte)0xe0, 
            (byte)0x14, (byte)0xc8, (byte)0xa8, (byte)0x6f, 
            (byte)0x0a, (byte)0xa6, (byte)0x35, (byte)0xd9, 
            (byte)0x47, (byte)0xac, (byte)0x9f, (byte)0xeb, 
            (byte)0xe8, (byte)0x3e, (byte)0xf4, (byte)0xe5, 
            (byte)0x59, (byte)0x66, (byte)0x14, (byte)0x4b, 
            (byte)0x2a, (byte)0x5a, (byte)0xb3, (byte)0x9d, 
            (byte)0xc1, (byte)0x38, (byte)0x14, (byte)0xb9, 
            (byte)0x4e, (byte)0x3a, (byte)0xb6, (byte)0xe1, 
            (byte)0x01, (byte)0xa3, (byte)0x4f, (byte)0x27
        }); 
        if (KeySizes.contains(algorithm.keySizes(), 25))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
            (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
            (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
            (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
            (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
            (byte)0x19
        }, 50, new byte[] { (byte)0xCD }, new byte[] {
            (byte)0x3e, (byte)0x8a, (byte)0x69, (byte)0xb7, 
            (byte)0x78, (byte)0x3c, (byte)0x25, (byte)0x85, 
            (byte)0x19, (byte)0x33, (byte)0xab, (byte)0x62, 
            (byte)0x90, (byte)0xaf, (byte)0x6c, (byte)0xa7, 
            (byte)0x7a, (byte)0x99, (byte)0x81, (byte)0x48, 
            (byte)0x08, (byte)0x50, (byte)0x00, (byte)0x9c, 
            (byte)0xc5, (byte)0x57, (byte)0x7c, (byte)0x6e, 
            (byte)0x1f, (byte)0x57, (byte)0x3b, (byte)0x4e, 
            (byte)0x68, (byte)0x01, (byte)0xdd, (byte)0x23, 
            (byte)0xc4, (byte)0xa7, (byte)0xd6, (byte)0x79, 
            (byte)0xcc, (byte)0xf8, (byte)0xa3, (byte)0x86, 
            (byte)0xc6, (byte)0x74, (byte)0xcf, (byte)0xfb
        }); 
        if (KeySizes.contains(algorithm.keySizes(), 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
        }, 1, "Test With Truncation", new byte[] {
            (byte)0x3a, (byte)0xbf, (byte)0x34, (byte)0xc3, 
            (byte)0x50, (byte)0x3b, (byte)0x2a, (byte)0x23, 
            (byte)0xa4, (byte)0x6e, (byte)0xfc, (byte)0x61, 
            (byte)0x9b, (byte)0xae, (byte)0xf8, (byte)0x97
        }); 
        if (KeySizes.contains(algorithm.keySizes(), 80))
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
            (byte)0x4e, (byte)0xce, (byte)0x08, (byte)0x44, 
            (byte)0x85, (byte)0x81, (byte)0x3e, (byte)0x90, 
            (byte)0x88, (byte)0xd2, (byte)0xc6, (byte)0x3a, 
            (byte)0x04, (byte)0x1b, (byte)0xc5, (byte)0xb4, 
            (byte)0x4f, (byte)0x9e, (byte)0xf1, (byte)0x01, 
            (byte)0x2a, (byte)0x2b, (byte)0x58, (byte)0x8f, 
            (byte)0x3c, (byte)0xd1, (byte)0x1f, (byte)0x05, 
            (byte)0x03, (byte)0x3a, (byte)0xc4, (byte)0xc6,
            (byte)0x0c, (byte)0x2e, (byte)0xf6, (byte)0xab, 
            (byte)0x40, (byte)0x30, (byte)0xfe, (byte)0x82, 
            (byte)0x96, (byte)0x24, (byte)0x8d, (byte)0xf1, 
            (byte)0x63, (byte)0xf4, (byte)0x49, (byte)0x52
        }); 
        if (KeySizes.contains(algorithm.keySizes(), 80))
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
            (byte)0x66, (byte)0x17, (byte)0x17, (byte)0x8e, 
            (byte)0x94, (byte)0x1f, (byte)0x02, (byte)0x0d, 
            (byte)0x35, (byte)0x1e, (byte)0x2f, (byte)0x25, 
            (byte)0x4e, (byte)0x8f, (byte)0xd3, (byte)0x2c, 
            (byte)0x60, (byte)0x24, (byte)0x20, (byte)0xfe, 
            (byte)0xb0, (byte)0xb8, (byte)0xfb, (byte)0x9a, 
            (byte)0xdc, (byte)0xce, (byte)0xbb, (byte)0x82, 
            (byte)0x46, (byte)0x1e, (byte)0x99, (byte)0xc5,
            (byte)0xa6, (byte)0x78, (byte)0xcc, (byte)0x31, 
            (byte)0xe7, (byte)0x99, (byte)0x17, (byte)0x6d, 
            (byte)0x38, (byte)0x60, (byte)0xe6, (byte)0x11, 
            (byte)0x0c, (byte)0x46, (byte)0x52, (byte)0x3e
        }); 
    }
}