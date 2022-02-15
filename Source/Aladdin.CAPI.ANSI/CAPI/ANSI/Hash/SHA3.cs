using System;

namespace Aladdin.CAPI.ANSI.Hash
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм хэширования SHA3
    ///////////////////////////////////////////////////////////////////////////////
    public class SHA3 : BlockHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        private static bool LFSR86540(byte[] LFSR)
        {
            bool result = ((LFSR[0] & 0x01) != 0);
            if ((LFSR[0] & 0x80) != 0)
            {
                LFSR[0] = (byte)((LFSR[0] << 1) ^ 0x71);
            }
            else LFSR[0] <<= 1; return result;
        }
        private static readonly ulong[] KeccakRoundConstants = new ulong[24];
        private static readonly int  [] KeccakRhoOffsets     = new int  [25];
        static SHA3() {
            byte[] LFSRstate = new byte[1]; LFSRstate[0] = 0x01;
            for (int i = 0; i < 24; i++)
            {
                KeccakRoundConstants[i] = 0;
                for (int j = 0; j < 7; j++)
                {
                    int bitPosition = (1 << j) - 1;
                    if (LFSR86540(LFSRstate))
                    {
                        KeccakRoundConstants[i] ^= 1UL << bitPosition;
                    }
                }
            }
            KeccakRhoOffsets[(0 % 5) + 5 * (0 % 5)] = 0;
            for (int t = 0, x = 1, y = 0; t < 24; t++)
            {
                KeccakRhoOffsets[(x % 5) + 5 * (y % 5)] = ((t + 1) * (t + 2) / 2) % 64;

                int newX = (0 * x + 1 * y) % 5;
                int newY = (2 * x + 3 * y) % 5;
            
                x = newX; y = newY;
            }
        }
        private static void Theta(ulong[] A)
        {
            ulong[] C = new ulong[5];
            for (int x = 0; x < 5; x++) 
            { 
                for (int y = 0; y < 5; y++) C[x] ^= A[x + 5 * y];
            }
            for (int x = 0; x < 5; x++)
            {
                ulong dX = (C[(x + 1) % 5] << 1) ^ (C[(x + 1) % 5] >> 63) ^ C[(x + 4) % 5];
            
                for (int y = 0; y < 5; y++) A[x + 5 * y] ^= dX;
            }
        }
        private static void Rho(ulong[] A)
        {
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    int index = x + 5 * y;
                    int offset = KeccakRhoOffsets[index];
                    if (offset != 0)
                    {
                        A[index] = (A[index] << offset) ^ (A[index] >> (64 - offset));
                    }
                }
            }
        }
        private static void Pi(ulong[] A)
        {
            ulong[] tempA = (ulong[])A.Clone();
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    A[y + 5 * ((2 * x + 3 * y) % 5)] = tempA[x + 5 * y];
                }
            }
        }
        private static void Chi(ulong[] A)
        {
            ulong[] chiC = new ulong[5];
            for (int y = 0; y < 5; y++)
            {
                for (int x = 0; x < 5; x++)
                {
                    chiC[x] = A[x + 5 * y] ^ (~A[((x + 1) % 5) + 5 * y] & A[((x + 2) % 5) + 5 * y]);
                }
                Array.Copy(chiC, 0, A, 5 * y, 5);
            }
        }
        private static void Iota(ulong[] A, int indexRound)
        {
            A[(0 % 5) + 5 * (0 % 5)] ^= KeccakRoundConstants[indexRound];
        }
        private static void KeccakPermutation(byte[] state)
        {
            ulong[] longState = new ulong[state.Length / 8];

            for (int i = 0; i < longState.Length; i++)
            {
                longState[i] = Math.Convert.ToUInt64(state, i * 8, Endian); 
            }
            for (int i = 0; i < 24; i++)
            {
                Theta(longState); Rho (longState   ); Pi(longState);
                Chi  (longState); Iota(longState, i);
            }
            for (int i = 0; i < longState.Length; i++)
            {
               Math.Convert.FromUInt64(longState[i], Endian, state, i * 8);
            }
        }
        // внутренее состояние
        private byte[] state = new byte[200]; 
    
        // размер хэш-значения и блока
        private int hashSize; private int blockSize;

        // конструктор
        public SHA3() : this(288) {} 

        // конструктор
        public SHA3(int bitLength) 
        {
            // указать размер хэш-значения
            hashSize = bitLength / 8; switch (bitLength)
            {
            // указать размер блока
            case 224: blockSize = (1600 - 2 * bitLength) / 8; return; 
            case 256: blockSize = (1600 - 2 * bitLength) / 8; return; 
            case 288: blockSize = (1600 - 2 * bitLength) / 8; return; 
            case 384: blockSize = (1600 - 2 * bitLength) / 8; return;
            case 512: blockSize = (1600 - 2 * bitLength) / 8; return; 
            }
            // при ошибке выбросить исключение
            throw new ArgumentException(); 
        }
        // размер хэш-значения в байтах
	    public override int HashSize { get { return hashSize; }}  
	
	    // размер блока в байтах
	    public override int BlockSize { get { return blockSize; }} 

	    // инициализировать алгоритм
	    public override void Init() 
        { 
            // инициализировать алгоритм
            base.Init(); Array.Clear(state, 0, state.Length);
        }
	    // обработать блок данных
	    protected override void Update(byte[] data, int dataOff)  
        {
            // выполнить сложение
            for (int i = 0; i < blockSize; i++) state[i] ^= data[i];

            // выполнить перестановку
            KeccakPermutation(state);
        }
	    // завершить преобразование
	    protected override void Finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
        {
            // для последнего полного блока 
            byte[] buffer = new byte[blockSize]; if (dataLen == blockSize) 
            {
                // обработать последний полный блок
                Update(data, dataOff); dataOff += blockSize; dataLen -= blockSize;
            }
            // выполнить дополнение
            buffer[dataLen] = (byte)0x01; buffer[blockSize - 1] = (byte)0x80; 
        
            // скопировать данные и обработать блок
            Array.Copy(data, dataOff, buffer, 0, dataLen); Update(buffer, 0); 

            // извлечь байты из состояния
            Array.Copy(state, 0, buffer, 0, blockSize);

            // указать число используемых байтов из сотояния
            int bytesAvailable = blockSize; int cb = blockSize; 
        
            // для всех частей хэш-значения
            for (int offset = 0; offset < hashSize; offset += cb, bytesAvailable -= cb)
            {
                // при отсутствии байтов из состояния выполнить перестановку
                if (bytesAvailable == 0) { KeccakPermutation(state);

                    // извлечь байты из состояния
                    Array.Copy(state, 0, buffer, 0, blockSize);
                
                    // указать число используемых байтов из сотояния
                    bytesAvailable = blockSize;
                }
                // определить число копируемых байтов
                if (cb > hashSize - offset) cb = hashSize - offset; 
            
                // скопировать байты хэш-значения
                Array.Copy(buffer, blockSize - bytesAvailable, buf, bufOff + offset, cb);
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тесты известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test224(CAPI.Hash hashAlgorithm) 
        {
            KnownTest(hashAlgorithm, 1, 
                "", new byte[] {
                (byte)0xf7, (byte)0x18, (byte)0x37, (byte)0x50, 
                (byte)0x2b, (byte)0xa8, (byte)0xe1, (byte)0x08, 
                (byte)0x37, (byte)0xbd, (byte)0xd8, (byte)0xd3, 
                (byte)0x65, (byte)0xad, (byte)0xb8, (byte)0x55, 
                (byte)0x91, (byte)0x89, (byte)0x56, (byte)0x02, 
                (byte)0xfc, (byte)0x55, (byte)0x2b, (byte)0x48, 
                (byte)0xb7, (byte)0x39, (byte)0x0a, (byte)0xbd
            });
            KnownTest(hashAlgorithm, 1, 
                "The quick brown fox jumps over the lazy dog", new byte[] {
                (byte)0x31, (byte)0x0a, (byte)0xee, (byte)0x6b, 
                (byte)0x30, (byte)0xc4, (byte)0x73, (byte)0x50, 
                (byte)0x57, (byte)0x6a, (byte)0xc2, (byte)0x87, 
                (byte)0x3f, (byte)0xa8, (byte)0x9f, (byte)0xd1, 
                (byte)0x90, (byte)0xcd, (byte)0xc4, (byte)0x88, 
                (byte)0x44, (byte)0x2f, (byte)0x3e, (byte)0xf6, 
                (byte)0x54, (byte)0xcf, (byte)0x23, (byte)0xfe
            });
            KnownTest(hashAlgorithm, 1, 
                "The quick brown fox jumps over the lazy dog.", new byte[] {
                (byte)0xc5, (byte)0x9d, (byte)0x4e, (byte)0xae, 
                (byte)0xac, (byte)0x72, (byte)0x86, (byte)0x71, 
                (byte)0xc6, (byte)0x35, (byte)0xff, (byte)0x64, 
                (byte)0x50, (byte)0x14, (byte)0xe2, (byte)0xaf, 
                (byte)0xa9, (byte)0x35, (byte)0xbe, (byte)0xbf, 
                (byte)0xfd, (byte)0xb5, (byte)0xfb, (byte)0xd2, 
                (byte)0x07, (byte)0xff, (byte)0xde, (byte)0xab
            });
        }
        public static void Test256(CAPI.Hash hashAlgorithm) 
        {
            KnownTest(hashAlgorithm, 1, 
                "", new byte[] {
                (byte)0xc5, (byte)0xd2, (byte)0x46, (byte)0x01, 
                (byte)0x86, (byte)0xf7, (byte)0x23, (byte)0x3c, 
                (byte)0x92, (byte)0x7e, (byte)0x7d, (byte)0xb2, 
                (byte)0xdc, (byte)0xc7, (byte)0x03, (byte)0xc0, 
                (byte)0xe5, (byte)0x00, (byte)0xb6, (byte)0x53, 
                (byte)0xca, (byte)0x82, (byte)0x27, (byte)0x3b, 
                (byte)0x7b, (byte)0xfa, (byte)0xd8, (byte)0x04, 
                (byte)0x5d, (byte)0x85, (byte)0xa4, (byte)0x70
            }); 
            KnownTest(hashAlgorithm, 1, 
                "The quick brown fox jumps over the lazy dog", new byte[] {
                (byte)0x4d, (byte)0x74, (byte)0x1b, (byte)0x6f, 
                (byte)0x1e, (byte)0xb2, (byte)0x9c, (byte)0xb2, 
                (byte)0xa9, (byte)0xb9, (byte)0x91, (byte)0x1c, 
                (byte)0x82, (byte)0xf5, (byte)0x6f, (byte)0xa8, 
                (byte)0xd7, (byte)0x3b, (byte)0x04, (byte)0x95, 
                (byte)0x9d, (byte)0x3d, (byte)0x9d, (byte)0x22, 
                (byte)0x28, (byte)0x95, (byte)0xdf, (byte)0x6c, 
                (byte)0x0b, (byte)0x28, (byte)0xaa, (byte)0x15
            });
            KnownTest(hashAlgorithm, 1, 
                "The quick brown fox jumps over the lazy dog.", new byte[] {
                (byte)0x57, (byte)0x89, (byte)0x51, (byte)0xe2, 
                (byte)0x4e, (byte)0xfd, (byte)0x62, (byte)0xa3, 
                (byte)0xd6, (byte)0x3a, (byte)0x86, (byte)0xf7, 
                (byte)0xcd, (byte)0x19, (byte)0xaa, (byte)0xa5, 
                (byte)0x3c, (byte)0x89, (byte)0x8f, (byte)0xe2, 
                (byte)0x87, (byte)0xd2, (byte)0x55, (byte)0x21, 
                (byte)0x33, (byte)0x22, (byte)0x03, (byte)0x70, 
                (byte)0x24, (byte)0x0b, (byte)0x57, (byte)0x2d
            });
        }
        public static void Test384(CAPI.Hash hashAlgorithm) 
        {
            KnownTest(hashAlgorithm, 1, 
                "", new byte[] {
                (byte)0x2c, (byte)0x23, (byte)0x14, (byte)0x6a,
                (byte)0x63, (byte)0xa2, (byte)0x9a, (byte)0xcf, 
                (byte)0x99, (byte)0xe7, (byte)0x3b, (byte)0x88, 
                (byte)0xf8, (byte)0xc2, (byte)0x4e, (byte)0xaa, 
                (byte)0x7d, (byte)0xc6, (byte)0x0a, (byte)0xa7, 
                (byte)0x71, (byte)0x78, (byte)0x0c, (byte)0xcc, 
                (byte)0x00, (byte)0x6a, (byte)0xfb, (byte)0xfa, 
                (byte)0x8f, (byte)0xe2, (byte)0x47, (byte)0x9b, 
                (byte)0x2d, (byte)0xd2, (byte)0xb2, (byte)0x13, 
                (byte)0x62, (byte)0x33, (byte)0x74, (byte)0x41, 
                (byte)0xac, (byte)0x12, (byte)0xb5, (byte)0x15, 
                (byte)0x91, (byte)0x19, (byte)0x57, (byte)0xff
            }); 
            KnownTest(hashAlgorithm, 1, 
                "The quick brown fox jumps over the lazy dog", new byte[] {
                (byte)0x28, (byte)0x39, (byte)0x90, (byte)0xfa, 
                (byte)0x9d, (byte)0x5f, (byte)0xb7, (byte)0x31, 
                (byte)0xd7, (byte)0x86, (byte)0xc5, (byte)0xbb, 
                (byte)0xee, (byte)0x94, (byte)0xea, (byte)0x4d, 
                (byte)0xb4, (byte)0x91, (byte)0x0f, (byte)0x18, 
                (byte)0xc6, (byte)0x2c, (byte)0x03, (byte)0xd1, 
                (byte)0x73, (byte)0xfc, (byte)0x0a, (byte)0x5e, 
                (byte)0x49, (byte)0x44, (byte)0x22, (byte)0xe8, 
                (byte)0xa0, (byte)0xb3, (byte)0xda, (byte)0x75, 
                (byte)0x74, (byte)0xda, (byte)0xe7, (byte)0xfa, 
                (byte)0x0b, (byte)0xaf, (byte)0x00, (byte)0x5e, 
                (byte)0x50, (byte)0x40, (byte)0x63, (byte)0xb3
            });
            KnownTest(hashAlgorithm, 1, 
                "The quick brown fox jumps over the lazy dog.", new byte[] {
                (byte)0x9a, (byte)0xd8, (byte)0xe1, (byte)0x73, 
                (byte)0x25, (byte)0x40, (byte)0x8e, (byte)0xdd, 
                (byte)0xb6, (byte)0xed, (byte)0xee, (byte)0x61, 
                (byte)0x47, (byte)0xf1, (byte)0x38, (byte)0x56, 
                (byte)0xad, (byte)0x81, (byte)0x9b, (byte)0xb7, 
                (byte)0x53, (byte)0x26, (byte)0x68, (byte)0xb6, 
                (byte)0x05, (byte)0xa2, (byte)0x4a, (byte)0x2d, 
                (byte)0x95, (byte)0x8f, (byte)0x88, (byte)0xbd, 
                (byte)0x5c, (byte)0x16, (byte)0x9e, (byte)0x56, 
                (byte)0xdc, (byte)0x4b, (byte)0x2f, (byte)0x89, 
                (byte)0xff, (byte)0xd3, (byte)0x25, (byte)0xf6, 
                (byte)0x00, (byte)0x6d, (byte)0x82, (byte)0x0b
            });
        }
        public static void Test512(CAPI.Hash hashAlgorithm) 
        {
            KnownTest(hashAlgorithm, 1, 
                "", new byte[] {
                (byte)0x0e, (byte)0xab, (byte)0x42, (byte)0xde, 
                (byte)0x4c, (byte)0x3c, (byte)0xeb, (byte)0x92, 
                (byte)0x35, (byte)0xfc, (byte)0x91, (byte)0xac, 
                (byte)0xff, (byte)0xe7, (byte)0x46, (byte)0xb2, 
                (byte)0x9c, (byte)0x29, (byte)0xa8, (byte)0xc3, 
                (byte)0x66, (byte)0xb7, (byte)0xc6, (byte)0x0e, 
                (byte)0x4e, (byte)0x67, (byte)0xc4, (byte)0x66, 
                (byte)0xf3, (byte)0x6a, (byte)0x43, (byte)0x04, 
                (byte)0xc0, (byte)0x0f, (byte)0xa9, (byte)0xca, 
                (byte)0xf9, (byte)0xd8, (byte)0x79, (byte)0x76, 
                (byte)0xba, (byte)0x46, (byte)0x9b, (byte)0xcb, 
                (byte)0xe0, (byte)0x67, (byte)0x13, (byte)0xb4, 
                (byte)0x35, (byte)0xf0, (byte)0x91, (byte)0xef, 
                (byte)0x27, (byte)0x69, (byte)0xfb, (byte)0x16, 
                (byte)0x0c, (byte)0xda, (byte)0xb3, (byte)0x3d, 
                (byte)0x36, (byte)0x70, (byte)0x68, (byte)0x0e
            }); 
            KnownTest(hashAlgorithm, 1, 
                "The quick brown fox jumps over the lazy dog", new byte[] {
                (byte)0xd1, (byte)0x35, (byte)0xbb, (byte)0x84, 
                (byte)0xd0, (byte)0x43, (byte)0x9d, (byte)0xba, 
                (byte)0xc4, (byte)0x32, (byte)0x24, (byte)0x7e, 
                (byte)0xe5, (byte)0x73, (byte)0xa2, (byte)0x3e, 
                (byte)0xa7, (byte)0xd3, (byte)0xc9, (byte)0xde, 
                (byte)0xb2, (byte)0xa9, (byte)0x68, (byte)0xeb, 
                (byte)0x31, (byte)0xd4, (byte)0x7c, (byte)0x4f, 
                (byte)0xb4, (byte)0x5f, (byte)0x1e, (byte)0xf4, 
                (byte)0x42, (byte)0x2d, (byte)0x6c, (byte)0x53, 
                (byte)0x1b, (byte)0x5b, (byte)0x9b, (byte)0xd6, 
                (byte)0xf4, (byte)0x49, (byte)0xeb, (byte)0xcc, 
                (byte)0x44, (byte)0x9e, (byte)0xa9, (byte)0x4d, 
                (byte)0x0a, (byte)0x8f, (byte)0x05, (byte)0xf6, 
                (byte)0x21, (byte)0x30, (byte)0xfd, (byte)0xa6, 
                (byte)0x12, (byte)0xda, (byte)0x53, (byte)0xc7, 
                (byte)0x96, (byte)0x59, (byte)0xf6, (byte)0x09
            });
            KnownTest(hashAlgorithm, 1, 
                "The quick brown fox jumps over the lazy dog.", new byte[] {
                (byte)0xab, (byte)0x71, (byte)0x92, (byte)0xd2, 
                (byte)0xb1, (byte)0x1f, (byte)0x51, (byte)0xc7, 
                (byte)0xdd, (byte)0x74, (byte)0x4e, (byte)0x7b, 
                (byte)0x34, (byte)0x41, (byte)0xfe, (byte)0xbf, 
                (byte)0x39, (byte)0x7c, (byte)0xa0, (byte)0x7b, 
                (byte)0xf8, (byte)0x12, (byte)0xcc, (byte)0xea, 
                (byte)0xe1, (byte)0x22, (byte)0xca, (byte)0x4d, 
                (byte)0xed, (byte)0x63, (byte)0x87, (byte)0x88, 
                (byte)0x90, (byte)0x64, (byte)0xf8, (byte)0xdb, 
                (byte)0x92, (byte)0x30, (byte)0xf1, (byte)0x73, 
                (byte)0xf6, (byte)0xd1, (byte)0xab, (byte)0x6e, 
                (byte)0x24, (byte)0xb6, (byte)0xe5, (byte)0x0f, 
                (byte)0x06, (byte)0x5b, (byte)0x03, (byte)0x9f, 
                (byte)0x79, (byte)0x9f, (byte)0x55, (byte)0x92, 
                (byte)0x36, (byte)0x0a, (byte)0x65, (byte)0x58, 
                (byte)0xeb, (byte)0x52, (byte)0xd7, (byte)0x60
            });
        }
    }
}
