using System; 
using System.Text; 

namespace Aladdin.CAPI.ANSI.Hash
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм хэширования SHA512
    ///////////////////////////////////////////////////////////////////////////////
    public class SHA2_512 : BlockHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // SHA-384 and SHA-512 Constants
        // (represent the first 64 bits of the fractional parts of the
        // cube roots of the first sixty-four prime numbers)
        //
        private static readonly ulong[] K = {
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
        private static ulong Ch(ulong x, ulong y, ulong z)
        {
            return ((x & y) ^ ((~x) & z));
        }
        private static ulong Maj(ulong x, ulong y, ulong z)
        {
            return ((x & y) ^ (x & z) ^ (y & z));
        }
        private static ulong Sum0(ulong x)
        {
            return ((x << 36)|(x >> 28)) ^ ((x << 30)|(x >> 34)) ^ ((x << 25)|(x >> 39));
        }
        private static ulong Sum1(ulong x)
        {
            return ((x << 50)|(x >> 14)) ^ ((x << 46)|(x >> 18)) ^ ((x << 23)|(x >> 41));
        }
        private static ulong Sigma0(ulong x)
        {
            return ((x << 63)|(x >> 1)) ^ ((x << 56)|(x >> 8)) ^ (x >> 7);
        }
        private static ulong Sigma1(ulong x)
        {
            return ((x << 45)|(x >> 19)) ^ ((x << 3)|(x >> 61)) ^ (x >> 6);
        }
        private long byteCount1; private long byteCount2;
    
        private ulong H1, H2, H3, H4, H5, H6, H7, H8;

        // размер хэш-значения в байтах
	    public override int HashSize { get { return 64; }}  
	
	    // размер блока в байтах
	    public override int BlockSize { get { return 128; }}

	    // инициализировать алгоритм
	    public override void Init() 
        { 
            Init(0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
                 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
                 0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
                 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
            ); 
        }
	    // инициализировать алгоритм
	    protected void Init(
            ulong H1, ulong H2, ulong H3, ulong H4, 
            ulong H5, ulong H6, ulong H7, ulong H8) 
        { 
            base.Init(); byteCount1 = 0; byteCount2 = 0;  

            // SHA-512 initial hash value
            // The first 64 bits of the fractional parts of the square roots
            // of the first eight prime numbers
            this.H1 = H1; this.H2 = H2; this.H3 = H3; this.H4 = H4;
            this.H5 = H5; this.H6 = H6; this.H7 = H7; this.H8 = H8;
        }
	    // обработать блок данных
	    protected override void Update(byte[] data, int dataOff)  
        {
            // выделить буфер требуемого размера
            ulong[] W = new ulong[80]; byteCount1 += BlockSize;
        
            // учесть возможность переноса
            if (byteCount1 == 0) byteCount2++;  

            // скопировать данные в буфер
            for (int i = 0; i < 16; i++)
            {
                // скопировать данные в буфер
                W[i] = Math.Convert.ToUInt64(data, dataOff + 8 * i, Endian); 
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
            ulong a = H1; ulong b = H2; ulong c = H3; ulong d = H4;
            ulong e = H5; ulong f = H6; ulong g = H7; ulong h = H8;

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
	    protected override void Finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
        {
            // для последнего полного блока 
            int blockSize = BlockSize; if (dataLen == blockSize) 
            {
                // обработать последний полный блок
                Update(data, dataOff); dataOff += blockSize; dataLen -= blockSize;
            }
            // увеличить размер данных
            byteCount1 += dataLen; long loCount = byteCount1 << 3;  
        
            // определить размер данных в битах
            long hiCount = (byteCount2 << 3) | (byteCount1 >> 61); 
        
            // выделить буфер для дополнения
            byte[] buffer = new byte[blockSize]; buffer[dataLen] = (byte)0x80;
        
            // скопировать данные
            Array.Copy(data, dataOff, buffer, 0, dataLen);

            // обработать дополненный блок
            if (dataLen >= 112) { Update(buffer, 0);

                // обнулить обработанный блок
                for (int i = 0; i < 112; i++) buffer[i] = 0; 
            }
            // закодировать размер в битах
            Math.Convert.FromUInt64((ulong)hiCount, Endian, buffer, 112); 
            Math.Convert.FromUInt64((ulong)loCount, Endian, buffer, 120); Update(buffer, 0);
        
            // выделить память для хэш-значения
            byte[] hash = new byte[64]; 
        
            // извлечь хэш-значение
            Math.Convert.FromUInt64(H1, Endian, buf, bufOff +  0); 
            Math.Convert.FromUInt64(H2, Endian, buf, bufOff +  8); 
            Math.Convert.FromUInt64(H3, Endian, buf, bufOff + 16); 
            Math.Convert.FromUInt64(H4, Endian, buf, bufOff + 24); 
            Math.Convert.FromUInt64(H5, Endian, buf, bufOff + 32); 
            Math.Convert.FromUInt64(H6, Endian, buf, bufOff + 40); 
            Math.Convert.FromUInt64(H7, Endian, buf, bufOff + 48); 
            Math.Convert.FromUInt64(H8, Endian, buf, bufOff + 56); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тесты известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Hash hashAlgorithm) 
        {
            KnownTest(hashAlgorithm, 1, 
                "abc", new byte[] {
                (byte)0xDD, (byte)0xAF, (byte)0x35, (byte)0xA1, 
                (byte)0x93, (byte)0x61, (byte)0x7A, (byte)0xBA, 
                (byte)0xCC, (byte)0x41, (byte)0x73, (byte)0x49, 
                (byte)0xAE, (byte)0x20, (byte)0x41, (byte)0x31, 
                (byte)0x12, (byte)0xE6, (byte)0xFA, (byte)0x4E, 
                (byte)0x89, (byte)0xA9, (byte)0x7E, (byte)0xA2, 
                (byte)0x0A, (byte)0x9E, (byte)0xEE, (byte)0xE6, 
                (byte)0x4B, (byte)0x55, (byte)0xD3, (byte)0x9A, 
                (byte)0x21, (byte)0x92, (byte)0x99, (byte)0x2A, 
                (byte)0x27, (byte)0x4F, (byte)0xC1, (byte)0xA8, 
                (byte)0x36, (byte)0xBA, (byte)0x3C, (byte)0x23, 
                (byte)0xA3, (byte)0xFE, (byte)0xEB, (byte)0xBD, 
                (byte)0x45, (byte)0x4D, (byte)0x44, (byte)0x23, 
                (byte)0x64, (byte)0x3C, (byte)0xE8, (byte)0x0E, 
                (byte)0x2A, (byte)0x9A, (byte)0xC9, (byte)0x4F, 
                (byte)0xA5, (byte)0x4C, (byte)0xA4, (byte)0x9F
            }); 
            KnownTest(hashAlgorithm, 1, 
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" + 
                "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", new byte[] {
                (byte)0x8E, (byte)0x95, (byte)0x9B, (byte)0x75, 
                (byte)0xDA, (byte)0xE3, (byte)0x13, (byte)0xDA, 
                (byte)0x8C, (byte)0xF4, (byte)0xF7, (byte)0x28, 
                (byte)0x14, (byte)0xFC, (byte)0x14, (byte)0x3F, 
                (byte)0x8F, (byte)0x77, (byte)0x79, (byte)0xC6, 
                (byte)0xEB, (byte)0x9F, (byte)0x7F, (byte)0xA1,
                (byte)0x72, (byte)0x99, (byte)0xAE, (byte)0xAD, 
                (byte)0xB6, (byte)0x88, (byte)0x90, (byte)0x18, 
                (byte)0x50, (byte)0x1D, (byte)0x28, (byte)0x9E, 
                (byte)0x49, (byte)0x00, (byte)0xF7, (byte)0xE4, 
                (byte)0x33, (byte)0x1B, (byte)0x99, (byte)0xDE, 
                (byte)0xC4, (byte)0xB5, (byte)0x43, (byte)0x3A, 
                (byte)0xC7, (byte)0xD3, (byte)0x29, (byte)0xEE, 
                (byte)0xB6, (byte)0xDD, (byte)0x26, (byte)0x54, 
                (byte)0x5E, (byte)0x96, (byte)0xE5, (byte)0x5B, 
                (byte)0x87, (byte)0x4B, (byte)0xE9, (byte)0x09
            }); 
            KnownTest(hashAlgorithm, 1000000, 
                "a", new byte[] {
                (byte)0xE7, (byte)0x18, (byte)0x48, (byte)0x3D, 
                (byte)0x0C, (byte)0xE7, (byte)0x69, (byte)0x64, 
                (byte)0x4E, (byte)0x2E, (byte)0x42, (byte)0xC7, 
                (byte)0xBC, (byte)0x15, (byte)0xB4, (byte)0x63, 
                (byte)0x8E, (byte)0x1F, (byte)0x98, (byte)0xB1, 
                (byte)0x3B, (byte)0x20, (byte)0x44, (byte)0x28,
                (byte)0x56, (byte)0x32, (byte)0xA8, (byte)0x03, 
                (byte)0xAF, (byte)0xA9, (byte)0x73, (byte)0xEB, 
                (byte)0xDE, (byte)0x0F, (byte)0xF2, (byte)0x44, 
                (byte)0x87, (byte)0x7E, (byte)0xA6, (byte)0x0A, 
                (byte)0x4C, (byte)0xB0, (byte)0x43, (byte)0x2C, 
                (byte)0xE5, (byte)0x77, (byte)0xC3, (byte)0x1B,
                (byte)0xEB, (byte)0x00, (byte)0x9C, (byte)0x5C, 
                (byte)0x2C, (byte)0x49, (byte)0xAA, (byte)0x2E, 
                (byte)0x4E, (byte)0xAD, (byte)0xB2, (byte)0x17, 
                (byte)0xAD, (byte)0x8C, (byte)0xC0, (byte)0x9B        
            }); 
            KnownTest(hashAlgorithm, 10, 
                "01234567012345670123456701234567" + 
                "01234567012345670123456701234567", new byte[] {
                (byte)0x89, (byte)0xD0, (byte)0x5B, (byte)0xA6, 
                (byte)0x32, (byte)0xC6, (byte)0x99, (byte)0xC3, 
                (byte)0x12, (byte)0x31, (byte)0xDE, (byte)0xD4, 
                (byte)0xFF, (byte)0xC1, (byte)0x27, (byte)0xD5, 
                (byte)0xA8, (byte)0x94, (byte)0xDA, (byte)0xD4, 
                (byte)0x12, (byte)0xC0, (byte)0xE0, (byte)0x24,
                (byte)0xDB, (byte)0x87, (byte)0x2D, (byte)0x1A, 
                (byte)0xBD, (byte)0x2B, (byte)0xA8, (byte)0x14, 
                (byte)0x1A, (byte)0x0F, (byte)0x85, (byte)0x07, 
                (byte)0x2A, (byte)0x9B, (byte)0xE1, (byte)0xE2, 
                (byte)0xAA, (byte)0x04, (byte)0xCF, (byte)0x33, 
                (byte)0xC7, (byte)0x65, (byte)0xCB, (byte)0x51, 
                (byte)0x08, (byte)0x13, (byte)0xA3, (byte)0x9C, 
                (byte)0xD5, (byte)0xA8, (byte)0x4C, (byte)0x4A, 
                (byte)0xCA, (byte)0xA6, (byte)0x4D, (byte)0x3F, 
                (byte)0x3F, (byte)0xB7, (byte)0xBA, (byte)0xE9
            }); 
            KnownTest(hashAlgorithm, 1, 
                new byte[] { (byte)0xD0 }, new byte[] {
                (byte)0x99, (byte)0x92, (byte)0x20, (byte)0x29, 
                (byte)0x38, (byte)0xE8, (byte)0x82, (byte)0xE7, 
                (byte)0x3E, (byte)0x20, (byte)0xF6, (byte)0xB6, 
                (byte)0x9E, (byte)0x68, (byte)0xA0, (byte)0xA7, 
                (byte)0x14, (byte)0x90, (byte)0x90, (byte)0x42, 
                (byte)0x3D, (byte)0x93, (byte)0xC8, (byte)0x1B, 
                (byte)0xAB, (byte)0x3F, (byte)0x21, (byte)0x67, 
                (byte)0x8D, (byte)0x4A, (byte)0xCE, (byte)0xEE, 
                (byte)0xE5, (byte)0x0E, (byte)0x4E, (byte)0x8C, 
                (byte)0xAF, (byte)0xAD, (byte)0xA4, (byte)0xC8, 
                (byte)0x5A, (byte)0x54, (byte)0xEA, (byte)0x83, 
                (byte)0x06, (byte)0x82, (byte)0x6C, (byte)0x4A,
                (byte)0xD6, (byte)0xE7, (byte)0x4C, (byte)0xEC, 
                (byte)0xE9, (byte)0x63, (byte)0x1B, (byte)0xFA, 
                (byte)0x8A, (byte)0x54, (byte)0x9B, (byte)0x4A, 
                (byte)0xB3, (byte)0xFB, (byte)0xBA, (byte)0x15
            }); 
            KnownTest(hashAlgorithm, 1, new byte[] { 
                (byte)0x8d, (byte)0x4e, (byte)0x3c, (byte)0x0e, 
                (byte)0x38, (byte)0x89, (byte)0x19, (byte)0x14, 
                (byte)0x91, (byte)0x81, (byte)0x6e, (byte)0x9d, 
                (byte)0x98, (byte)0xbf, (byte)0xf0, (byte)0xa0
            }, new byte[] {
                (byte)0xCB, (byte)0x0B, (byte)0x67, (byte)0xA4, 
                (byte)0xB8, (byte)0x71, (byte)0x2C, (byte)0xD7, 
                (byte)0x3C, (byte)0x9A, (byte)0xAB, (byte)0xC0, 
                (byte)0xB1, (byte)0x99, (byte)0xE9, (byte)0x26, 
                (byte)0x9B, (byte)0x20, (byte)0x84, (byte)0x4A, 
                (byte)0xFB, (byte)0x75, (byte)0xAC, (byte)0xBD,
                (byte)0xD1, (byte)0xC1, (byte)0x53, (byte)0xC9, 
                (byte)0x82, (byte)0x89, (byte)0x24, (byte)0xC3, 
                (byte)0xDD, (byte)0xED, (byte)0xAA, (byte)0xFE, 
                (byte)0x66, (byte)0x9C, (byte)0x5F, (byte)0xDD, 
                (byte)0x0B, (byte)0xC6, (byte)0x6F, (byte)0x63, 
                (byte)0x0F, (byte)0x67, (byte)0x73, (byte)0x98,
                (byte)0x82, (byte)0x13, (byte)0xEB, (byte)0x1B, 
                (byte)0x16, (byte)0xF5, (byte)0x17, (byte)0xAD, 
                (byte)0x0D, (byte)0xE4, (byte)0xB2, (byte)0xF0, 
                (byte)0xC9, (byte)0x5C, (byte)0x90, (byte)0xF8        
            }); 
            KnownTest(hashAlgorithm, 1, new byte[] { 
                (byte)0xa5, (byte)0x5f, (byte)0x20, (byte)0xc4, 
                (byte)0x11, (byte)0xaa, (byte)0xd1, (byte)0x32, 
                (byte)0x80, (byte)0x7a, (byte)0x50, (byte)0x2d, 
                (byte)0x65, (byte)0x82, (byte)0x4e, (byte)0x31,
                (byte)0xa2, (byte)0x30, (byte)0x54, (byte)0x32, 
                (byte)0xaa, (byte)0x3d, (byte)0x06, (byte)0xd3, 
                (byte)0xe2, (byte)0x82, (byte)0xa8, (byte)0xd8, 
                (byte)0x4e, (byte)0x0d, (byte)0xe1, (byte)0xde,
                (byte)0x69, (byte)0x74, (byte)0xbf, (byte)0x49, 
                (byte)0x54, (byte)0x69, (byte)0xfc, (byte)0x7f, 
                (byte)0x33, (byte)0x8f, (byte)0x80, (byte)0x54, 
                (byte)0xd5, (byte)0x8c, (byte)0x26, (byte)0xc4,
                (byte)0x93, (byte)0x60, (byte)0xc3, (byte)0xe8, 
                (byte)0x7a, (byte)0xf5, (byte)0x65, (byte)0x23, 
                (byte)0xac, (byte)0xf6, (byte)0xd8, (byte)0x9d, 
                (byte)0x03, (byte)0xe5, (byte)0x6f, (byte)0xf2,
                (byte)0xf8, (byte)0x68, (byte)0x00, (byte)0x2b, 
                (byte)0xc3, (byte)0xe4, (byte)0x31, (byte)0xed, 
                (byte)0xc4, (byte)0x4d, (byte)0xf2, (byte)0xf0, 
                (byte)0x22, (byte)0x3d, (byte)0x4b, (byte)0xb3,
                (byte)0xb2, (byte)0x43, (byte)0x58, (byte)0x6e, 
                (byte)0x1a, (byte)0x7d, (byte)0x92, (byte)0x49, 
                (byte)0x36, (byte)0x69, (byte)0x4f, (byte)0xcb, 
                (byte)0xba, (byte)0xf8, (byte)0x8d, (byte)0x95,
                (byte)0x19, (byte)0xe4, (byte)0xeb, (byte)0x50, 
                (byte)0xa6, (byte)0x44, (byte)0xf8, (byte)0xe4, 
                (byte)0xf9, (byte)0x5e, (byte)0xb0, (byte)0xea, 
                (byte)0x95, (byte)0xbc, (byte)0x44, (byte)0x65,
                (byte)0xc8, (byte)0x82, (byte)0x1a, (byte)0xac, 
                (byte)0xd2, (byte)0xfe, (byte)0x15, (byte)0xab, 
                (byte)0x49, (byte)0x81, (byte)0x16, (byte)0x4b, 
                (byte)0xbb, (byte)0x6d, (byte)0xc3, (byte)0x2f,
                (byte)0x96, (byte)0x90, (byte)0x87, (byte)0xa1, 
                (byte)0x45, (byte)0xb0, (byte)0xd9, (byte)0xcc, 
                (byte)0x9c, (byte)0x67, (byte)0xc2, (byte)0x2b, 
                (byte)0x76, (byte)0x32, (byte)0x99, (byte)0x41,
                (byte)0x9c, (byte)0xc4, (byte)0x12, (byte)0x8b, 
                (byte)0xe9, (byte)0xa0, (byte)0x77, (byte)0xb3, 
                (byte)0xac, (byte)0xe6, (byte)0x34, (byte)0x06, 
                (byte)0x4e, (byte)0x6d, (byte)0x99, (byte)0x28,
                (byte)0x35, (byte)0x13, (byte)0xdc, (byte)0x06, 
                (byte)0xe7, (byte)0x51, (byte)0x5d, (byte)0x0d, 
                (byte)0x73, (byte)0x13, (byte)0x2e, (byte)0x9a, 
                (byte)0x0d, (byte)0xc6, (byte)0xd3, (byte)0xb1,
                (byte)0xf8, (byte)0xb2, (byte)0x46, (byte)0xf1, 
                (byte)0xa9, (byte)0x8a, (byte)0x3f, (byte)0xc7, 
                (byte)0x29, (byte)0x41, (byte)0xb1, (byte)0xe3, 
                (byte)0xbb, (byte)0x20, (byte)0x98, (byte)0xe8,
                (byte)0xbf, (byte)0x16, (byte)0xf2, (byte)0x68, 
                (byte)0xd6, (byte)0x4f, (byte)0x0b, (byte)0x0f, 
                (byte)0x47, (byte)0x07, (byte)0xfe, (byte)0x1e, 
                (byte)0xa1, (byte)0xa1, (byte)0x79, (byte)0x1b,
                (byte)0xa2, (byte)0xf3, (byte)0xc0, (byte)0xc7, 
                (byte)0x58, (byte)0xe5, (byte)0xf5, (byte)0x51, 
                (byte)0x86, (byte)0x3a, (byte)0x96, (byte)0xc9, 
                (byte)0x49, (byte)0xad, (byte)0x47, (byte)0xd7,
                (byte)0xfb, (byte)0x40, (byte)0xd2
            }, new byte[] {
                (byte)0xC6, (byte)0x65, (byte)0xBE, (byte)0xFB, 
                (byte)0x36, (byte)0xDA, (byte)0x18, (byte)0x9D, 
                (byte)0x78, (byte)0x82, (byte)0x2D, (byte)0x10, 
                (byte)0x52, (byte)0x8C, (byte)0xBF, (byte)0x3B, 
                (byte)0x12, (byte)0xB3, (byte)0xEE, (byte)0xF7, 
                (byte)0x26, (byte)0x03, (byte)0x99, (byte)0x09,
                (byte)0xC1, (byte)0xA1, (byte)0x6A, (byte)0x27, 
                (byte)0x0D, (byte)0x48, (byte)0x71, (byte)0x93, 
                (byte)0x77, (byte)0x96, (byte)0x6B, (byte)0x95, 
                (byte)0x7A, (byte)0x87, (byte)0x8E, (byte)0x72, 
                (byte)0x05, (byte)0x84, (byte)0x77, (byte)0x9A, 
                (byte)0x62, (byte)0x82, (byte)0x5C, (byte)0x18,
                (byte)0xDA, (byte)0x26, (byte)0x41, (byte)0x5E, 
                (byte)0x49, (byte)0xA7, (byte)0x17, (byte)0x6A, 
                (byte)0x89, (byte)0x4E, (byte)0x75, (byte)0x10, 
                (byte)0xFD, (byte)0x14, (byte)0x51, (byte)0xF5
            }); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // HMAC-SHA2-512
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC(Mac algorithm)
        {
            if (KeySizes.Contains(algorithm.KeySizes, 20))
            Mac.KnownTest(algorithm, new byte[] { 
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
            }, 1, "Hi There", new byte[] {
                (byte)0x87, (byte)0xaa, (byte)0x7c, (byte)0xde, 
                (byte)0xa5, (byte)0xef, (byte)0x61, (byte)0x9d, 
                (byte)0x4f, (byte)0xf0, (byte)0xb4, (byte)0x24, 
                (byte)0x1a, (byte)0x1d, (byte)0x6c, (byte)0xb0, 
                (byte)0x23, (byte)0x79, (byte)0xf4, (byte)0xe2, 
                (byte)0xce, (byte)0x4e, (byte)0xc2, (byte)0x78, 
                (byte)0x7a, (byte)0xd0, (byte)0xb3, (byte)0x05, 
                (byte)0x45, (byte)0xe1, (byte)0x7c, (byte)0xde, 
                (byte)0xda, (byte)0xa8, (byte)0x33, (byte)0xb7, 
                (byte)0xd6, (byte)0xb8, (byte)0xa7, (byte)0x02, 
                (byte)0x03, (byte)0x8b, (byte)0x27, (byte)0x4e, 
                (byte)0xae, (byte)0xa3, (byte)0xf4, (byte)0xe4, 
                (byte)0xbe, (byte)0x9d, (byte)0x91, (byte)0x4e, 
                (byte)0xeb, (byte)0x61, (byte)0xf1, (byte)0x70, 
                (byte)0x2e, (byte)0x69, (byte)0x6c, (byte)0x20, 
                (byte)0x3a, (byte)0x12, (byte)0x68, (byte)0x54
            }); 
            if (KeySizes.Contains(algorithm.KeySizes, 4))
            Mac.KnownTest(algorithm, Encoding.UTF8.GetBytes("Jefe"), 
                1, "what do ya want for nothing?", new byte[] {
                (byte)0x16, (byte)0x4b, (byte)0x7a, (byte)0x7b, 
                (byte)0xfc, (byte)0xf8, (byte)0x19, (byte)0xe2, 
                (byte)0xe3, (byte)0x95, (byte)0xfb, (byte)0xe7, 
                (byte)0x3b, (byte)0x56, (byte)0xe0, (byte)0xa3, 
                (byte)0x87, (byte)0xbd, (byte)0x64, (byte)0x22, 
                (byte)0x2e, (byte)0x83, (byte)0x1f, (byte)0xd6, 
                (byte)0x10, (byte)0x27, (byte)0x0c, (byte)0xd7, 
                (byte)0xea, (byte)0x25, (byte)0x05, (byte)0x54, 
                (byte)0x97, (byte)0x58, (byte)0xbf, (byte)0x75, 
                (byte)0xc0, (byte)0x5a, (byte)0x99, (byte)0x4a, 
                (byte)0x6d, (byte)0x03, (byte)0x4f, (byte)0x65, 
                (byte)0xf8, (byte)0xf0, (byte)0xe6, (byte)0xfd, 
                (byte)0xca, (byte)0xea, (byte)0xb1, (byte)0xa3, 
                (byte)0x4d, (byte)0x4a, (byte)0x6b, (byte)0x4b, 
                (byte)0x63, (byte)0x6e, (byte)0x07, (byte)0x0a, 
                (byte)0x38, (byte)0xbc, (byte)0xe7, (byte)0x37
            }); 
            if (KeySizes.Contains(algorithm.KeySizes, 20))
            Mac.KnownTest(algorithm, new byte[] { 
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
            }, 50, new byte[] { (byte)0xDD }, new byte[] {
                (byte)0xfa, (byte)0x73, (byte)0xb0, (byte)0x08, 
                (byte)0x9d, (byte)0x56, (byte)0xa2, (byte)0x84, 
                (byte)0xef, (byte)0xb0, (byte)0xf0, (byte)0x75, 
                (byte)0x6c, (byte)0x89, (byte)0x0b, (byte)0xe9, 
                (byte)0xb1, (byte)0xb5, (byte)0xdb, (byte)0xdd, 
                (byte)0x8e, (byte)0xe8, (byte)0x1a, (byte)0x36, 
                (byte)0x55, (byte)0xf8, (byte)0x3e, (byte)0x33, 
                (byte)0xb2, (byte)0x27, (byte)0x9d, (byte)0x39, 
                (byte)0xbf, (byte)0x3e, (byte)0x84, (byte)0x82, 
                (byte)0x79, (byte)0xa7, (byte)0x22, (byte)0xc8, 
                (byte)0x06, (byte)0xb4, (byte)0x85, (byte)0xa4, 
                (byte)0x7e, (byte)0x67, (byte)0xc8, (byte)0x07, 
                (byte)0xb9, (byte)0x46, (byte)0xa3, (byte)0x37, 
                (byte)0xbe, (byte)0xe8, (byte)0x94, (byte)0x26, 
                (byte)0x74, (byte)0x27, (byte)0x88, (byte)0x59, 
                (byte)0xe1, (byte)0x32, (byte)0x92, (byte)0xfb
            }); 
            if (KeySizes.Contains(algorithm.KeySizes, 25))
            Mac.KnownTest(algorithm, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
                (byte)0x19
            }, 50, new byte[] { (byte)0xCD }, new byte[] {
                (byte)0xb0, (byte)0xba, (byte)0x46, (byte)0x56, 
                (byte)0x37, (byte)0x45, (byte)0x8c, (byte)0x69, 
                (byte)0x90, (byte)0xe5, (byte)0xa8, (byte)0xc5, 
                (byte)0xf6, (byte)0x1d, (byte)0x4a, (byte)0xf7, 
                (byte)0xe5, (byte)0x76, (byte)0xd9, (byte)0x7f, 
                (byte)0xf9, (byte)0x4b, (byte)0x87, (byte)0x2d, 
                (byte)0xe7, (byte)0x6f, (byte)0x80, (byte)0x50, 
                (byte)0x36, (byte)0x1e, (byte)0xe3, (byte)0xdb, 
                (byte)0xa9, (byte)0x1c, (byte)0xa5, (byte)0xc1, 
                (byte)0x1a, (byte)0xa2, (byte)0x5e, (byte)0xb4, 
                (byte)0xd6, (byte)0x79, (byte)0x27, (byte)0x5c, 
                (byte)0xc5, (byte)0x78, (byte)0x80, (byte)0x63,
                (byte)0xa5, (byte)0xf1, (byte)0x97, (byte)0x41, 
                (byte)0x12, (byte)0x0c, (byte)0x4f, (byte)0x2d, 
                (byte)0xe2, (byte)0xad, (byte)0xeb, (byte)0xeb, 
                (byte)0x10, (byte)0xa2, (byte)0x98, (byte)0xdd
            }); 
            if (KeySizes.Contains(algorithm.KeySizes, 20))
            Mac.KnownTest(algorithm, new byte[] { 
                (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
                (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
            }, 1, "Test With Truncation", new byte[] {
                (byte)0x41, (byte)0x5f, (byte)0xad, (byte)0x62, 
                (byte)0x71, (byte)0x58, (byte)0x0a, (byte)0x53, 
                (byte)0x1d, (byte)0x41, (byte)0x79, (byte)0xbc, 
                (byte)0x89, (byte)0x1d, (byte)0x87, (byte)0xa6
            }); 
            if (KeySizes.Contains(algorithm.KeySizes, 80))
            Mac.KnownTest(algorithm, new byte[] { 
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
                (byte)0x80, (byte)0xb2, (byte)0x42, (byte)0x63, 
                (byte)0xc7, (byte)0xc1, (byte)0xa3, (byte)0xeb, 
                (byte)0xb7, (byte)0x14, (byte)0x93, (byte)0xc1, 
                (byte)0xdd, (byte)0x7b, (byte)0xe8, (byte)0xb4, 
                (byte)0x9b, (byte)0x46, (byte)0xd1, (byte)0xf4, 
                (byte)0x1b, (byte)0x4a, (byte)0xee, (byte)0xc1, 
                (byte)0x12, (byte)0x1b, (byte)0x01, (byte)0x37, 
                (byte)0x83, (byte)0xf8, (byte)0xf3, (byte)0x52, 
                (byte)0x6b, (byte)0x56, (byte)0xd0, (byte)0x37, 
                (byte)0xe0, (byte)0x5f, (byte)0x25, (byte)0x98, 
                (byte)0xbd, (byte)0x0f, (byte)0xd2, (byte)0x21, 
                (byte)0x5d, (byte)0x6a, (byte)0x1e, (byte)0x52, 
                (byte)0x95, (byte)0xe6, (byte)0x4f, (byte)0x73, 
                (byte)0xf6, (byte)0x3f, (byte)0x0a, (byte)0xec, 
                (byte)0x8b, (byte)0x91, (byte)0x5a, (byte)0x98, 
                (byte)0x5d, (byte)0x78, (byte)0x65, (byte)0x98
            }); 
            if (KeySizes.Contains(algorithm.KeySizes, 80))
            Mac.KnownTest(algorithm, new byte[] { 
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
                (byte)0xe3, (byte)0x7b, (byte)0x6a, (byte)0x77, 
                (byte)0x5d, (byte)0xc8, (byte)0x7d, (byte)0xba, 
                (byte)0xa4, (byte)0xdf, (byte)0xa9, (byte)0xf9, 
                (byte)0x6e, (byte)0x5e, (byte)0x3f, (byte)0xfd, 
                (byte)0xde, (byte)0xbd, (byte)0x71, (byte)0xf8, 
                (byte)0x86, (byte)0x72, (byte)0x89, (byte)0x86, 
                (byte)0x5d, (byte)0xf5, (byte)0xa3, (byte)0x2d, 
                (byte)0x20, (byte)0xcd, (byte)0xc9, (byte)0x44, 
                (byte)0xb6, (byte)0x02, (byte)0x2c, (byte)0xac, 
                (byte)0x3c, (byte)0x49, (byte)0x82, (byte)0xb1, 
                (byte)0x0d, (byte)0x5e, (byte)0xeb, (byte)0x55, 
                (byte)0xc3, (byte)0xe4, (byte)0xde, (byte)0x15, 
                (byte)0x13, (byte)0x46, (byte)0x76, (byte)0xfb, 
                (byte)0x6d, (byte)0xe0, (byte)0x44, (byte)0x60, 
                (byte)0x65, (byte)0xc9, (byte)0x74, (byte)0x40, 
                (byte)0xfa, (byte)0x8c, (byte)0x6a, (byte)0x58
            }); 
        }
    }
}