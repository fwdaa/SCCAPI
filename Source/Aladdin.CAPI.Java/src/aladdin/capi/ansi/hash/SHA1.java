package aladdin.capi.ansi.hash;
import aladdin.math.*;
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования SHA1
///////////////////////////////////////////////////////////////////////////////
public class SHA1 extends BlockHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    //
    // Additive constants
    //
    private static final int Y1 = 0x5a827999;
    private static final int Y2 = 0x6ed9eba1;
    private static final int Y3 = 0x8f1bbcdc;
    private static final int Y4 = 0xca62c1d6;
   
    private static int f(int u, int v, int w)
    {
        return ((u & v) | ((~u) & w));
    }
    private static int h(int u, int v, int w)
    {
        return (u ^ v ^ w);
    }
    private static int g(int u, int v, int w)
    {
        return ((u & v) | (u & w) | (v & w));
    }
    private long byteCount; private int H1, H2, H3, H4, H5;
    
    // размер хэш-значения в байтах
	@Override public int hashSize() { return 20; }  
	
	// размер блока в байтах
	@Override public int blockSize() { return 64; } 

	// инициализировать алгоритм
	@Override public void init() throws IOException
    { 
        super.init(); byteCount = 0;  

        H1 = 0x67452301; H2 = 0xefcdab89;
        H3 = 0x98badcfe; H4 = 0x10325476;
        H5 = 0xc3d2e1f0;
    }
	// обработать блок данных
	@Override protected void update(byte[] data, int dataOff)  
    {
        // выделить буфер требуемого размера
        int[] X = new int[80]; byteCount += blockSize();
        
        // скопировать данные в буфер
        for (int i = 0; i < 16; i++)
        {
            // скопировать данные в буфер
            X[i] = Convert.toInt32(data, dataOff + 4 * i, ENDIAN); 
        }
        //
        // expand 16 word block into 80 word block.
        //
        for (int i = 16; i < 80; i++)
        {
            int t = X[i - 3] ^ X[i - 8] ^ X[i - 14] ^ X[i - 16];
            X[i] = t << 1 | t >>> 31;
        }
        //
        // set up working variables.
        //
        int A = H1; int B = H2; int C = H3; int D = H4; int E = H5;
        //
        // round 1
        //
        int idx = 0;
        
        for (int j = 0; j < 4; j++)
        {
            // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + f(B, C, D) + X[idx++] + Y1;
            B = B << 30 | B >>> 2;
        
            D += (E << 5 | E >>> 27) + f(A, B, C) + X[idx++] + Y1;
            A = A << 30 | A >>> 2;
       
            C += (D << 5 | D >>> 27) + f(E, A, B) + X[idx++] + Y1;
            E = E << 30 | E >>> 2;
       
            B += (C << 5 | C >>> 27) + f(D, E, A) + X[idx++] + Y1;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + f(C, D, E) + X[idx++] + Y1;
            C = C << 30 | C >>> 2;
        }
        //
        // round 2
        //
        for (int j = 0; j < 4; j++)
        {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + h(B, C, D) + X[idx++] + Y2;
            B = B << 30 | B >>> 2;   
            
            D += (E << 5 | E >>> 27) + h(A, B, C) + X[idx++] + Y2;
            A = A << 30 | A >>> 2;
            
            C += (D << 5 | D >>> 27) + h(E, A, B) + X[idx++] + Y2;
            E = E << 30 | E >>> 2;
            
            B += (C << 5 | C >>> 27) + h(D, E, A) + X[idx++] + Y2;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + h(C, D, E) + X[idx++] + Y2;
            C = C << 30 | C >>> 2;
        }
        //
        // round 3
        //
        for (int j = 0; j < 4; j++)
        {
            // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + g(B, C, D) + X[idx++] + Y3;
            B = B << 30 | B >>> 2;
            
            D += (E << 5 | E >>> 27) + g(A, B, C) + X[idx++] + Y3;
            A = A << 30 | A >>> 2;
            
            C += (D << 5 | D >>> 27) + g(E, A, B) + X[idx++] + Y3;
            E = E << 30 | E >>> 2;
            
            B += (C << 5 | C >>> 27) + g(D, E, A) + X[idx++] + Y3;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + g(C, D, E) + X[idx++] + Y3;
            C = C << 30 | C >>> 2;
        }
        //
        // round 4
        //
        for (int j = 0; j <= 3; j++)
        {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + h(B, C, D) + X[idx++] + Y4;
            B = B << 30 | B >>> 2;
            
            D += (E << 5 | E >>> 27) + h(A, B, C) + X[idx++] + Y4;
            A = A << 30 | A >>> 2;
            
            C += (D << 5 | D >>> 27) + h(E, A, B) + X[idx++] + Y4;
            E = E << 30 | E >>> 2;
            
            B += (C << 5 | C >>> 27) + h(D, E, A) + X[idx++] + Y4;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + h(C, D, E) + X[idx++] + Y4;
            C = C << 30 | C >>> 2;
        }
        H1 += A; H2 += B; H3 += C; H4 += D; H5 += E;
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
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Hash hashAlgorithm) throws Exception
    {
        knownTest(hashAlgorithm, 1, 
            "abc", new byte[] {
            (byte)0xA9, (byte)0x99, (byte)0x3E, (byte)0x36, 
            (byte)0x47, (byte)0x06, (byte)0x81, (byte)0x6A, 
            (byte)0xBA, (byte)0x3E, (byte)0x25, (byte)0x71, 
            (byte)0x78, (byte)0x50, (byte)0xC2, (byte)0x6C, 
            (byte)0x9C, (byte)0xD0, (byte)0xD8, (byte)0x9D
        }); 
        knownTest(hashAlgorithm, 1, 
            "abcdbcdecdefdefgefghfghighij" + 
            "hijkijkljklmklmnlmnomnopnopq", new byte[] {
            (byte)0x84, (byte)0x98, (byte)0x3E, (byte)0x44, 
            (byte)0x1C, (byte)0x3B, (byte)0xD2, (byte)0x6E, 
            (byte)0xBA, (byte)0xAE, (byte)0x4A, (byte)0xA1, 
            (byte)0xF9, (byte)0x51, (byte)0x29, (byte)0xE5, 
            (byte)0xE5, (byte)0x46, (byte)0x70, (byte)0xF1,
        }); 
        knownTest(hashAlgorithm, 1000000, 
            "a", new byte[] {
            (byte)0x34, (byte)0xAA, (byte)0x97, (byte)0x3C, 
            (byte)0xD4, (byte)0xC4, (byte)0xDA, (byte)0xA4, 
            (byte)0xF6, (byte)0x1E, (byte)0xEB, (byte)0x2B, 
            (byte)0xDB, (byte)0xAD, (byte)0x27, (byte)0x31, 
            (byte)0x65, (byte)0x34, (byte)0x01, (byte)0x6F
        }); 
        knownTest(hashAlgorithm, 10, 
            "01234567012345670123456701234567" + 
            "01234567012345670123456701234567", new byte[] {
            (byte)0xDE, (byte)0xA3, (byte)0x56, (byte)0xA2, 
            (byte)0xCD, (byte)0xDD, (byte)0x90, (byte)0xC7, 
            (byte)0xA7, (byte)0xEC, (byte)0xED, (byte)0xC5, 
            (byte)0xEB, (byte)0xB5, (byte)0x63, (byte)0x93, 
            (byte)0x4F, (byte)0x46, (byte)0x04, (byte)0x52 
        }); 
        knownTest(hashAlgorithm, 1, 
            new byte[] { 0x5E }, new byte[] {
            (byte)0x5E, (byte)0x6F, (byte)0x80, (byte)0xA3, 
            (byte)0x4A, (byte)0x97, (byte)0x98, (byte)0xCA, 
            (byte)0xFC, (byte)0x6A, (byte)0x5D, (byte)0xB9, 
            (byte)0x6C, (byte)0xC5, (byte)0x7B, (byte)0xA4, 
            (byte)0xC4, (byte)0xDB, (byte)0x59, (byte)0xC2
        }); 
        knownTest(hashAlgorithm, 1, new byte[] { 
            (byte)0x9a, (byte)0x7d, (byte)0xfd, (byte)0xf1, 
            (byte)0xec, (byte)0xea, (byte)0xd0, (byte)0x6e, 
            (byte)0xd6, (byte)0x46, (byte)0xaa, (byte)0x55, 
            (byte)0xfe, (byte)0x75, (byte)0x71, (byte)0x46 
        }, new byte[] {
            (byte)0x82, (byte)0xAB, (byte)0xFF, (byte)0x66, 
            (byte)0x05, (byte)0xDB, (byte)0xE1, (byte)0xC1, 
            (byte)0x7D, (byte)0xEF, (byte)0x12, (byte)0xA3, 
            (byte)0x94, (byte)0xFA, (byte)0x22, (byte)0xA8, 
            (byte)0x2B, (byte)0x54, (byte)0x4A, (byte)0x35
        }); 
        knownTest(hashAlgorithm, 1, new byte[] { 
            (byte)0xf7, (byte)0x8f, (byte)0x92, (byte)0x14, 
            (byte)0x1b, (byte)0xcd, (byte)0x17, (byte)0x0a, 
            (byte)0xe8, (byte)0x9b, (byte)0x4f, (byte)0xba, 
            (byte)0x15, (byte)0xa1, (byte)0xd5, (byte)0x9f,
            (byte)0x3f, (byte)0xd8, (byte)0x4d, (byte)0x22, 
            (byte)0x3c, (byte)0x92, (byte)0x51, (byte)0xbd, 
            (byte)0xac, (byte)0xbb, (byte)0xae, (byte)0x61, 
            (byte)0xd0, (byte)0x5e, (byte)0xd1, (byte)0x15,
            (byte)0xa0, (byte)0x6a, (byte)0x7c, (byte)0xe1, 
            (byte)0x17, (byte)0xb7, (byte)0xbe, (byte)0xea, 
            (byte)0xd2, (byte)0x44, (byte)0x21, (byte)0xde, 
            (byte)0xd9, (byte)0xc3, (byte)0x25, (byte)0x92, 
            (byte)0xbd, (byte)0x57, (byte)0xed, (byte)0xea, 
            (byte)0xe3, (byte)0x9c, (byte)0x39, (byte)0xfa, 
            (byte)0x1f, (byte)0xe8, (byte)0x94, (byte)0x6a, 
            (byte)0x84, (byte)0xd0, (byte)0xcf, (byte)0x1f, 
            (byte)0x7b, (byte)0xee, (byte)0xad, (byte)0x17, 
            (byte)0x13, (byte)0xe2, (byte)0xe0, (byte)0x95, 
            (byte)0x98, (byte)0x97, (byte)0x34, (byte)0x7f, 
            (byte)0x67, (byte)0xc8, (byte)0x0b, (byte)0x04,
            (byte)0x00, (byte)0xc2, (byte)0x09, (byte)0x81, 
            (byte)0x5d, (byte)0x6b, (byte)0x10, (byte)0xa6, 
            (byte)0x83, (byte)0x83, (byte)0x6f, (byte)0xd5, 
            (byte)0x56, (byte)0x2a, (byte)0x56, (byte)0xca,
            (byte)0xb1, (byte)0xa2, (byte)0x8e, (byte)0x81, 
            (byte)0xb6, (byte)0x57, (byte)0x66, (byte)0x54, 
            (byte)0x63, (byte)0x1c, (byte)0xf1, (byte)0x65, 
            (byte)0x66, (byte)0xb8, (byte)0x6e, (byte)0x3b, 
            (byte)0x33, (byte)0xa1, (byte)0x08, (byte)0xb0, 
            (byte)0x53, (byte)0x07, (byte)0xc0, (byte)0x0a, 
            (byte)0xff, (byte)0x14, (byte)0xa7, (byte)0x68, 
            (byte)0xed, (byte)0x73, (byte)0x50, (byte)0x60, 
            (byte)0x6a, (byte)0x0f, (byte)0x85, (byte)0xe6, 
            (byte)0xa9, (byte)0x1d, (byte)0x39, (byte)0x6f, 
            (byte)0x5b, (byte)0x5c, (byte)0xbe, (byte)0x57, 
            (byte)0x7f, (byte)0x9b, (byte)0x38, (byte)0x80, 
            (byte)0x7c, (byte)0x7d, (byte)0x52, (byte)0x3d, 
            (byte)0x6d, (byte)0x79, (byte)0x2f, (byte)0x6e, 
            (byte)0xbc, (byte)0x24, (byte)0xa4, (byte)0xec, 
            (byte)0xf2, (byte)0xb3, (byte)0xa4, (byte)0x27, 
            (byte)0xcd, (byte)0xbb, (byte)0xfb
        }, new byte[] {
            (byte)0xCB, (byte)0x00, (byte)0x82, (byte)0xC8, 
            (byte)0xF1, (byte)0x97, (byte)0xD2, (byte)0x60, 
            (byte)0x99, (byte)0x1B, (byte)0xA6, (byte)0xA4, 
            (byte)0x60, (byte)0xE7, (byte)0x6E, (byte)0x20, 
            (byte)0x2B, (byte)0xAD, (byte)0x27, (byte)0xB3 
        }); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // HMAC-SHA1
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
            (byte)0xb6, (byte)0x17, (byte)0x31, (byte)0x86, 
            (byte)0x55, (byte)0x05, (byte)0x72, (byte)0x64, 
            (byte)0xe2, (byte)0x8b, (byte)0xc0, (byte)0xb6, 
            (byte)0xfb, (byte)0x37, (byte)0x8c, (byte)0x8e, 
            (byte)0xf1, (byte)0x46, (byte)0xbe, (byte)0x00        
        }); 
        if (KeySizes.contains(algorithm.keySizes(), 4))
        Mac.knownTest(algorithm, "Jefe".getBytes("UTF-8"), 
            1, "what do ya want for nothing?", new byte[] {
            (byte)0xef, (byte)0xfc, (byte)0xdf, (byte)0x6a, 
            (byte)0xe5, (byte)0xeb, (byte)0x2f, (byte)0xa2, 
            (byte)0xd2, (byte)0x74, (byte)0x16, (byte)0xd5, 
            (byte)0xf1, (byte)0x84, (byte)0xdf, (byte)0x9c, 
            (byte)0x25, (byte)0x9a, (byte)0x7c, (byte)0x79            
        }); 
        if (KeySizes.contains(algorithm.keySizes(), 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
        }, 50, new byte[] { (byte)0xDD }, new byte[] {
            (byte)0x12, (byte)0x5d, (byte)0x73, (byte)0x42, 
            (byte)0xb9, (byte)0xac, (byte)0x11, (byte)0xcd, 
            (byte)0x91, (byte)0xa3, (byte)0x9a, (byte)0xf4, 
            (byte)0x8a, (byte)0xa1, (byte)0x7b, (byte)0x4f, 
            (byte)0x63, (byte)0xf1, (byte)0x75, (byte)0xd3        
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
            (byte)0x4c, (byte)0x90, (byte)0x07, (byte)0xf4, 
            (byte)0x02, (byte)0x62, (byte)0x50, (byte)0xc6, 
            (byte)0xbc, (byte)0x84, (byte)0x14, (byte)0xf9, 
            (byte)0xbf, (byte)0x50, (byte)0xc8, (byte)0x6c, 
            (byte)0x2d, (byte)0x72, (byte)0x35, (byte)0xda        
        }); 
        if (KeySizes.contains(algorithm.keySizes(), 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
        }, 1, "Test With Truncation", new byte[] {
            (byte)0x4c, (byte)0x1a, (byte)0x03, (byte)0x42, 
            (byte)0x4b, (byte)0x55, (byte)0xe0, (byte)0x7f, 
            (byte)0xe7, (byte)0xf2, (byte)0x7b, (byte)0xe1, 
            (byte)0xd5, (byte)0x8b, (byte)0xb9, (byte)0x32, 
            (byte)0x4a, (byte)0x9a, (byte)0x5a, (byte)0x04        
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
        }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
            (byte)0xaa, (byte)0x4a, (byte)0xe5, (byte)0xe1, 
            (byte)0x52, (byte)0x72, (byte)0xd0, (byte)0x0e, 
            (byte)0x95, (byte)0x70, (byte)0x56, (byte)0x37, 
            (byte)0xce, (byte)0x8a, (byte)0x3b, (byte)0x55, 
            (byte)0xed, (byte)0x40, (byte)0x21, (byte)0x12        
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
        }, 1, "Test Using Larger Than Block-Size Key and Larger " + 
              "Than One Block-Size Data", new byte[] {
            (byte)0xe8, (byte)0xe9, (byte)0x9d, (byte)0x0f, 
            (byte)0x45, (byte)0x23, (byte)0x7d, (byte)0x78, 
            (byte)0x6d, (byte)0x6b, (byte)0xba, (byte)0xa7, 
            (byte)0x96, (byte)0x5c, (byte)0x78, (byte)0x08, 
            (byte)0xbb, (byte)0xff, (byte)0x1a, (byte)0x91
        }); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // HMAC-PBKDF2
    ////////////////////////////////////////////////////////////////////////////
    public static void testHMAC_PBKDF2(Factory factory, SecurityStore scope) throws Exception
    {
        PBKDF2.test(factory, scope, null, "password", new byte[] { 
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x78, (byte)0x56, (byte)0x34, (byte)0x12 
        }, 5, new byte[] {
           (byte)0xD1, (byte)0xDA, (byte)0xA7, (byte)0x86, 
           (byte)0x15, (byte)0xF2, (byte)0x87, (byte)0xE6 
        }); 
        PBKDF2.test(factory, scope, null, 
            "All n-entities must communicate with other " + 
            "n-entities via n-1 entiteeheehees", new byte[] { 
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x78, (byte)0x56, (byte)0x34, (byte)0x12 
        }, 500, new byte[] {
            (byte)0x6A, (byte)0x89, (byte)0x70, (byte)0xBF, 
            (byte)0x68, (byte)0xC9, (byte)0x2C, (byte)0xAE, 
            (byte)0xA8, (byte)0x4A, (byte)0x8D, (byte)0xF2, 
            (byte)0x85, (byte)0x10, (byte)0x85, (byte)0x86, 
            (byte)0x07, (byte)0x12, (byte)0x63, (byte)0x80, 
            (byte)0xCC, (byte)0x47, (byte)0xAB, (byte)0x2D                    
        }); 
        PBKDF2.test(factory, scope, null, "password", 
            "salt".getBytes("UTF-8"), 1, new byte[] {
            (byte)0x0c, (byte)0x60, (byte)0xc8, (byte)0x0f, 
            (byte)0x96, (byte)0x1f, (byte)0x0e, (byte)0x71, 
            (byte)0xf3, (byte)0xa9, (byte)0xb5, (byte)0x24, 
            (byte)0xaf, (byte)0x60, (byte)0x12, (byte)0x06, 
            (byte)0x2f, (byte)0xe0, (byte)0x37, (byte)0xa6
        }); 
        PBKDF2.test(factory, scope, null, "password", 
            "salt".getBytes("UTF-8"), 2, new byte[] {
            (byte)0xea, (byte)0x6c, (byte)0x01, (byte)0x4d, 
            (byte)0xc7, (byte)0x2d, (byte)0x6f, (byte)0x8c, 
            (byte)0xcd, (byte)0x1e, (byte)0xd9, (byte)0x2a, 
            (byte)0xce, (byte)0x1d, (byte)0x41, (byte)0xf0, 
            (byte)0xd8, (byte)0xde, (byte)0x89, (byte)0x57         
        }); 
        PBKDF2.test(factory, scope, null, "password", 
            "salt".getBytes("UTF-8"), 4096, new byte[] {
            (byte)0x4b, (byte)0x00, (byte)0x79, (byte)0x01, 
            (byte)0xb7, (byte)0x65, (byte)0x48, (byte)0x9a,
            (byte)0xbe, (byte)0xad, (byte)0x49, (byte)0xd9, 
            (byte)0x26, (byte)0xf7, (byte)0x21, (byte)0xd0,
            (byte)0x65, (byte)0xa4, (byte)0x29, (byte)0xc1        
        }); 
/*      PBKDF2.test(factory, scope, null, "password", 
            "salt".getBytes("UTF-8"), 16777216, new byte[] {
            (byte)0xee, (byte)0xfe, (byte)0x3d, (byte)0x61, 
            (byte)0xcd, (byte)0x4d, (byte)0xa4, (byte)0xe4, 
            (byte)0xe9, (byte)0x94, (byte)0x5b, (byte)0x3d, 
            (byte)0x6b, (byte)0xa2, (byte)0x15, (byte)0x8c,
            (byte)0x26, (byte)0x34, (byte)0xe9, (byte)0x84         
        }); 
*/      PBKDF2.test(factory, scope, null, "passwordPASSWORDpassword", 
            "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes("UTF-8"), 
            4096, new byte[] {
            (byte)0x3d, (byte)0x2e, (byte)0xec, (byte)0x4f, 
            (byte)0xe4, (byte)0x1c, (byte)0x84, (byte)0x9b, 
            (byte)0x80, (byte)0xc8, (byte)0xd8, (byte)0x36, 
            (byte)0x62, (byte)0xc0, (byte)0xe4, (byte)0x4a,
            (byte)0x8b, (byte)0x29, (byte)0x1a, (byte)0x96, 
            (byte)0x4c, (byte)0xf2, (byte)0xf0, (byte)0x70, 
            (byte)0x38         
        }); 
        PBKDF2.test(factory, scope, null, "pass\0word", 
            "sa\0lt".getBytes("UTF-8"), 4096, new byte[] {
            (byte)0x56, (byte)0xfa, (byte)0x6a, (byte)0xa7, 
            (byte)0x55, (byte)0x48, (byte)0x09, (byte)0x9d, 
            (byte)0xcc, (byte)0x37, (byte)0xd7, (byte)0xf0, 
            (byte)0x34, (byte)0x25, (byte)0xe0, (byte)0xc3        
        }); 
    }
}
