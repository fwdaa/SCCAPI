using System; 
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования RC4
    ///////////////////////////////////////////////////////////////////////////
    public class RC4 : StreamCipher
    {
        // тип ключа
        public override SecretKeyFactory KeyFactory  
        { 
            // тип ключа
            get { return new Keys.RC4(CAPI.KeySizes.Range(1, 256)); }
        }
        protected override IRand CreatePRF(ISecretKey key)
        { 
            // проверить тип ключа
		    byte[] value = key.Value; if (value == null)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
            // проверить размер ключа
            if (value.Length < 1 || value.Length > 256)
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException(); 
            }
            return new PRF(key); 
        }
    
        ///////////////////////////////////////////////////////////////////////
        // Алгоритм генерации 
        ///////////////////////////////////////////////////////////////////////
        [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
        public class PRF : RefObject, IRand
        {
            // используемый ключ и состояние алгоритма
            private byte[] key; private byte[] state;
        
            // вспомогательные переменные
            private int x; private int y;
       
            // конструктор
            public PRF(ISecretKey key)
            {
                // получить значение ключа 
			    this.key = key.Value; state = new byte[256]; x = 0; y = 0;
            
			    // проверить тип ключа
                if (this.key == null) throw new InvalidKeyException();

                for (int i = 0; i < state.Length; i++) state[i] = (byte)i;
            
                for (int i = 0, j = 0; i < state.Length; i++)
                {
                    j = (this.key[i % this.key.Length] + state[i] + j) & 0xff; 

                    // do the byte-swap inline
                    byte temp = state[i]; state[i] = state[j]; state[j] = temp;
                }
            }
            // сгенерировать последовательность
            public void Generate(byte[] buffer, int off, int length)
            {
                for (int i = 0; i < length; i++)
                {
                    x = (x + 1) & 0xff; y = (state[x] + y) & 0xff;

                    byte temp = state[x]; state[x] = state[y]; state[y] = temp;  

                    buffer[i] = state[(state[x] + state[y]) & 0xff]; 
                }
            }
            // сгенерировать последовательность
            public byte[] Generate(int length)
            {
                // выделить буфер требуемого размера
                byte[] buffer = new byte[length]; 
            
                // сгенерировать последовательность
                Generate(buffer, 0, length); return buffer; 
            }
            // описатель окна
            public object Window { get { return null; }}
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Cipher cipher) 
        {
            int[] keySizes = cipher.KeyFactory.KeySizes; 

            if (CAPI.KeySizes.Contains(keySizes, 5))
            KnownTest(cipher, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05
            }, 
            new Fragment(  0, new byte[] {
                (byte)0xb2, (byte)0x39, (byte)0x63, (byte)0x05,
                (byte)0xf0, (byte)0x3d, (byte)0xc0, (byte)0x27, 
                (byte)0xcc, (byte)0xc3, (byte)0x52, (byte)0x4a,
                (byte)0x0a, (byte)0x11, (byte)0x18, (byte)0xa8
            }),
            new Fragment( 16, new byte[] {
                (byte)0x69, (byte)0x82, (byte)0x94, (byte)0x4f,
                (byte)0x18, (byte)0xfc, (byte)0x82, (byte)0xd5, 
                (byte)0x89, (byte)0xc4, (byte)0x03, (byte)0xa4,
                (byte)0x7a, (byte)0x0d, (byte)0x09, (byte)0x19
            }),
             new Fragment( 240, new byte[] {
                (byte)0x28, (byte)0xcb, (byte)0x11, (byte)0x32,
                (byte)0xc9, (byte)0x6c, (byte)0xe2, (byte)0x86, 
                (byte)0x42, (byte)0x1d, (byte)0xca, (byte)0xad,
                (byte)0xb8, (byte)0xb6, (byte)0x9e, (byte)0xae
            }),
            new Fragment( 256, new byte[] {
                (byte)0x1c, (byte)0xfc, (byte)0xf6, (byte)0x2b,
                (byte)0x03, (byte)0xed, (byte)0xdb, (byte)0x64, 
                (byte)0x1d, (byte)0x77, (byte)0xdf, (byte)0xcf,
                (byte)0x7f, (byte)0x8d, (byte)0x8c, (byte)0x93
            }),
            new Fragment( 496, new byte[] {
                (byte)0x42, (byte)0xb7, (byte)0xd0, (byte)0xcd,
                (byte)0xd9, (byte)0x18, (byte)0xa8, (byte)0xa3, 
                (byte)0x3d, (byte)0xd5, (byte)0x17, (byte)0x81,
                (byte)0xc8, (byte)0x1f, (byte)0x40, (byte)0x41
            }),
            new Fragment( 512, new byte[] {
                (byte)0x64, (byte)0x59, (byte)0x84, (byte)0x44,
                (byte)0x32, (byte)0xa7, (byte)0xda, (byte)0x92, 
                (byte)0x3c, (byte)0xfb, (byte)0x3e, (byte)0xb4,
                (byte)0x98, (byte)0x06, (byte)0x61, (byte)0xf6
            }),
            new Fragment( 752, new byte[] {
                (byte)0xec, (byte)0x10, (byte)0x32, (byte)0x7b,
                (byte)0xde, (byte)0x2b, (byte)0xee, (byte)0xfd, 
                (byte)0x18, (byte)0xf9, (byte)0x27, (byte)0x76,
                (byte)0x80, (byte)0x45, (byte)0x7e, (byte)0x22
            }),
            new Fragment( 768, new byte[] {
                (byte)0xeb, (byte)0x62, (byte)0x63, (byte)0x8d,
                (byte)0x4f, (byte)0x0b, (byte)0xa1, (byte)0xfe, 
                (byte)0x9f, (byte)0xca, (byte)0x20, (byte)0xe0,
                (byte)0x5b, (byte)0xf8, (byte)0xff, (byte)0x2b
            }),
            new Fragment(1008, new byte[] {
                (byte)0x45, (byte)0x12, (byte)0x90, (byte)0x48,
                (byte)0xe6, (byte)0xa0, (byte)0xed, (byte)0x0b, 
                (byte)0x56, (byte)0xb4, (byte)0x90, (byte)0x33,
                (byte)0x8f, (byte)0x07, (byte)0x8d, (byte)0xa5
            }),
            new Fragment(1024, new byte[] {
                (byte)0x30, (byte)0xab, (byte)0xbc, (byte)0xc7,
                (byte)0xc2, (byte)0x0b, (byte)0x01, (byte)0x60, 
                (byte)0x9f, (byte)0x23, (byte)0xee, (byte)0x2d,
                (byte)0x5f, (byte)0x6b, (byte)0xb7, (byte)0xdf
            }),
            new Fragment(1520, new byte[] {
                (byte)0x32, (byte)0x94, (byte)0xf7, (byte)0x44,
                (byte)0xd8, (byte)0xf9, (byte)0x79, (byte)0x05, 
                (byte)0x07, (byte)0xe7, (byte)0x0f, (byte)0x62,
                (byte)0xe5, (byte)0xbb, (byte)0xce, (byte)0xea
            }),
            new Fragment(1536, new byte[] {
                (byte)0xd8, (byte)0x72, (byte)0x9d, (byte)0xb4,
                (byte)0x18, (byte)0x82, (byte)0x25, (byte)0x9b, 
                (byte)0xee, (byte)0x4f, (byte)0x82, (byte)0x53,
                (byte)0x25, (byte)0xf5, (byte)0xa1, (byte)0x30
            }),
            new Fragment(2032, new byte[] {
                (byte)0x1e, (byte)0xb1, (byte)0x4a, (byte)0x0c,
                (byte)0x13, (byte)0xb3, (byte)0xbf, (byte)0x47, 
                (byte)0xfa, (byte)0x2a, (byte)0x0b, (byte)0xa9,
                (byte)0x3a, (byte)0xd4, (byte)0x5b, (byte)0x8b
            }),
            new Fragment(2048, new byte[] {
                (byte)0xcc, (byte)0x58, (byte)0x2f, (byte)0x8b,
                (byte)0xa9, (byte)0xf2, (byte)0x65, (byte)0xe2, 
                (byte)0xb1, (byte)0xbe, (byte)0x91, (byte)0x12,
                (byte)0xe9, (byte)0x75, (byte)0xd2, (byte)0xd7
            }),
            new Fragment(3056, new byte[] {
                (byte)0xf2, (byte)0xe3, (byte)0x0f, (byte)0x9b,
                (byte)0xd1, (byte)0x02, (byte)0xec, (byte)0xbf, 
                (byte)0x75, (byte)0xaa, (byte)0xad, (byte)0xe9,
                (byte)0xbc, (byte)0x35, (byte)0xc4, (byte)0x3c
            }),
            new Fragment(3072, new byte[] {
                (byte)0xec, (byte)0x0e, (byte)0x11, (byte)0xc4,
                (byte)0x79, (byte)0xdc, (byte)0x32, (byte)0x9d, 
                (byte)0xc8, (byte)0xda, (byte)0x79, (byte)0x68,
                (byte)0xfe, (byte)0x96, (byte)0x56, (byte)0x81
            }),
            new Fragment(4080, new byte[] {
                (byte)0x06, (byte)0x83, (byte)0x26, (byte)0xa2,
                (byte)0x11, (byte)0x84, (byte)0x16, (byte)0xd2, 
                (byte)0x1f, (byte)0x9d, (byte)0x04, (byte)0xb2,
                (byte)0xcd, (byte)0x1c, (byte)0xa0, (byte)0x50
            }),
            new Fragment(4096, new byte[] {
                (byte)0xff, (byte)0x25, (byte)0xb5, (byte)0x89,
                (byte)0x95, (byte)0x99, (byte)0x67, (byte)0x07, 
                (byte)0xe5, (byte)0x1f, (byte)0xbd, (byte)0xf0,
                (byte)0x8b, (byte)0x34, (byte)0xd8, (byte)0x75
            }));
            if (CAPI.KeySizes.Contains(keySizes, 5))
            KnownTest(cipher, new byte[] { 
                (byte)0x83, (byte)0x32, (byte)0x22, (byte)0x77, 
                (byte)0x2a
            },
            new Fragment(  0, new byte[] {
                (byte)0x80, (byte)0xad, (byte)0x97, (byte)0xbd,
                (byte)0xc9, (byte)0x73, (byte)0xdf, (byte)0x8a, 
                (byte)0x2e, (byte)0x87, (byte)0x9e, (byte)0x92,
                (byte)0xa4, (byte)0x97, (byte)0xef, (byte)0xda
            }),
            new Fragment( 16, new byte[] {
                (byte)0x20, (byte)0xf0, (byte)0x60, (byte)0xc2,
                (byte)0xf2, (byte)0xe5, (byte)0x12, (byte)0x65, 
                (byte)0x01, (byte)0xd3, (byte)0xd4, (byte)0xfe,
                (byte)0xa1, (byte)0x0d, (byte)0x5f, (byte)0xc0
            }),
            new Fragment( 240, new byte[] {
                (byte)0xfa, (byte)0xa1, (byte)0x48, (byte)0xe9,
                (byte)0x90, (byte)0x46, (byte)0x18, (byte)0x1f, 
                (byte)0xec, (byte)0x6b, (byte)0x20, (byte)0x85,
                (byte)0xf3, (byte)0xb2, (byte)0x0e, (byte)0xd9
            }),
            new Fragment( 256, new byte[] {
                (byte)0xf0, (byte)0xda, (byte)0xf5, (byte)0xba,
                (byte)0xb3, (byte)0xd5, (byte)0x96, (byte)0x83, 
                (byte)0x98, (byte)0x57, (byte)0x84, (byte)0x6f,
                (byte)0x73, (byte)0xfb, (byte)0xfe, (byte)0x5a
            }),
            new Fragment( 496, new byte[] {
                (byte)0x1c, (byte)0x7e, (byte)0x2f, (byte)0xc4,
                (byte)0x63, (byte)0x92, (byte)0x32, (byte)0xfe, 
                (byte)0x29, (byte)0x75, (byte)0x84, (byte)0xb2,
                (byte)0x96, (byte)0x99, (byte)0x6b, (byte)0xc8
            }),
            new Fragment( 512, new byte[] {
                (byte)0x3d, (byte)0xb9, (byte)0xb2, (byte)0x49,
                (byte)0x40, (byte)0x6c, (byte)0xc8, (byte)0xed, 
                (byte)0xff, (byte)0xac, (byte)0x55, (byte)0xcc,
                (byte)0xd3, (byte)0x22, (byte)0xba, (byte)0x12
            }),
            new Fragment( 752, new byte[] {
                (byte)0xe4, (byte)0xf9, (byte)0xf7, (byte)0xe0,
                (byte)0x06, (byte)0x61, (byte)0x54, (byte)0xbb, 
                (byte)0xd1, (byte)0x25, (byte)0xb7, (byte)0x45,
                (byte)0x56, (byte)0x9b, (byte)0xc8, (byte)0x97
            }),
            new Fragment( 768, new byte[] {
                (byte)0x75, (byte)0xd5, (byte)0xef, (byte)0x26,
                (byte)0x2b, (byte)0x44, (byte)0xc4, (byte)0x1a, 
                (byte)0x9c, (byte)0xf6, (byte)0x3a, (byte)0xe1,
                (byte)0x45, (byte)0x68, (byte)0xe1, (byte)0xb9
            }),
            new Fragment(1008, new byte[] {
                (byte)0x6d, (byte)0xa4, (byte)0x53, (byte)0xdb,
                (byte)0xf8, (byte)0x1e, (byte)0x82, (byte)0x33, 
                (byte)0x4a, (byte)0x3d, (byte)0x88, (byte)0x66,
                (byte)0xcb, (byte)0x50, (byte)0xa1, (byte)0xe3
            }),
            new Fragment(1024, new byte[] {
                (byte)0x78, (byte)0x28, (byte)0xd0, (byte)0x74,
                (byte)0x11, (byte)0x9c, (byte)0xab, (byte)0x5c, 
                (byte)0x22, (byte)0xb2, (byte)0x94, (byte)0xd7,
                (byte)0xa9, (byte)0xbf, (byte)0xa0, (byte)0xbb
            }),
            new Fragment(1520, new byte[] {
                (byte)0xad, (byte)0xb8, (byte)0x9c, (byte)0xea,
                (byte)0x9a, (byte)0x15, (byte)0xfb, (byte)0xe6, 
                (byte)0x17, (byte)0x29, (byte)0x5b, (byte)0xd0,
                (byte)0x4b, (byte)0x8c, (byte)0xa0, (byte)0x5c
            }),
            new Fragment(1536, new byte[] {
                (byte)0x62, (byte)0x51, (byte)0xd8, (byte)0x7f,
                (byte)0xd4, (byte)0xaa, (byte)0xae, (byte)0x9a, 
                (byte)0x7e, (byte)0x4a, (byte)0xd5, (byte)0xc2,
                (byte)0x17, (byte)0xd3, (byte)0xf3, (byte)0x00
            }),
            new Fragment(2032, new byte[] {
                (byte)0xe7, (byte)0x11, (byte)0x9b, (byte)0xd6,
                (byte)0xdd, (byte)0x9b, (byte)0x22, (byte)0xaf, 
                (byte)0xe8, (byte)0xf8, (byte)0x95, (byte)0x85,
                (byte)0x43, (byte)0x28, (byte)0x81, (byte)0xe2
            }),
            new Fragment(2048, new byte[] {
                (byte)0x78, (byte)0x5b, (byte)0x60, (byte)0xfd,
                (byte)0x7e, (byte)0xc4, (byte)0xe9, (byte)0xfc, 
                (byte)0xb6, (byte)0x54, (byte)0x5f, (byte)0x35,
                (byte)0x0d, (byte)0x66, (byte)0x0f, (byte)0xab
            }),
            new Fragment(3056, new byte[] {
                (byte)0xaf, (byte)0xec, (byte)0xc0, (byte)0x37,
                (byte)0xfd, (byte)0xb7, (byte)0xb0, (byte)0x83, 
                (byte)0x8e, (byte)0xb3, (byte)0xd7, (byte)0x0b,
                (byte)0xcd, (byte)0x26, (byte)0x83, (byte)0x82
            }),
            new Fragment(3072, new byte[] {
                (byte)0xdb, (byte)0xc1, (byte)0xa7, (byte)0xb4,
                (byte)0x9d, (byte)0x57, (byte)0x35, (byte)0x8c, 
                (byte)0xc9, (byte)0xfa, (byte)0x6d, (byte)0x61,
                (byte)0xd7, (byte)0x3b, (byte)0x7c, (byte)0xf0
            }),
            new Fragment(4080, new byte[] {
                (byte)0x63, (byte)0x49, (byte)0xd1, (byte)0x26,
                (byte)0xa3, (byte)0x7a, (byte)0xfc, (byte)0xba, 
                (byte)0x89, (byte)0x79, (byte)0x4f, (byte)0x98,
                (byte)0x04, (byte)0x91, (byte)0x4f, (byte)0xdc
            }),
            new Fragment(4096, new byte[] {
                (byte)0xbf, (byte)0x42, (byte)0xc3, (byte)0x01,
                (byte)0x8c, (byte)0x2f, (byte)0x7c, (byte)0x66, 
                (byte)0xbf, (byte)0xde, (byte)0x52, (byte)0x49,
                (byte)0x75, (byte)0x76, (byte)0x81, (byte)0x15
            }));
            if (CAPI.KeySizes.Contains(keySizes, 7))
            KnownTest(cipher, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07
            },
            new Fragment(  0, new byte[] {
                (byte)0x29, (byte)0x3f, (byte)0x02, (byte)0xd4,
                (byte)0x7f, (byte)0x37, (byte)0xc9, (byte)0xb6, 
                (byte)0x33, (byte)0xf2, (byte)0xaf, (byte)0x52,
                (byte)0x85, (byte)0xfe, (byte)0xb4, (byte)0x6b
            }),
            new Fragment( 16, new byte[] {
                (byte)0xe6, (byte)0x20, (byte)0xf1, (byte)0x39,
                (byte)0x0d, (byte)0x19, (byte)0xbd, (byte)0x84, 
                (byte)0xe2, (byte)0xe0, (byte)0xfd, (byte)0x75,
                (byte)0x20, (byte)0x31, (byte)0xaf, (byte)0xc1
            }),
            new Fragment( 240, new byte[] {
                (byte)0x91, (byte)0x4f, (byte)0x02, (byte)0x53,
                (byte)0x1c, (byte)0x92, (byte)0x18, (byte)0x81, 
                (byte)0x0d, (byte)0xf6, (byte)0x0f, (byte)0x67,
                (byte)0xe3, (byte)0x38, (byte)0x15, (byte)0x4c
            }),
            new Fragment( 256, new byte[] {
                (byte)0xd0, (byte)0xfd, (byte)0xb5, (byte)0x83,
                (byte)0x07, (byte)0x3c, (byte)0xe8, (byte)0x5a, 
                (byte)0xb8, (byte)0x39, (byte)0x17, (byte)0x74,
                (byte)0x0e, (byte)0xc0, (byte)0x11, (byte)0xd5
            }),
            new Fragment( 496, new byte[] {
                (byte)0x75, (byte)0xf8, (byte)0x14, (byte)0x11,
                (byte)0xe8, (byte)0x71, (byte)0xcf, (byte)0xfa, 
                (byte)0x70, (byte)0xb9, (byte)0x0c, (byte)0x74,
                (byte)0xc5, (byte)0x92, (byte)0xe4, (byte)0x54
            }),
            new Fragment( 512, new byte[] {
                (byte)0x0b, (byte)0xb8, (byte)0x72, (byte)0x02,
                (byte)0x93, (byte)0x8d, (byte)0xad, (byte)0x60, 
                (byte)0x9e, (byte)0x87, (byte)0xa5, (byte)0xa1,
                (byte)0xb0, (byte)0x79, (byte)0xe5, (byte)0xe4
            }),
            new Fragment( 752, new byte[] {
                (byte)0xc2, (byte)0x91, (byte)0x12, (byte)0x46,
                (byte)0xb6, (byte)0x12, (byte)0xe7, (byte)0xe7, 
                (byte)0xb9, (byte)0x03, (byte)0xdf, (byte)0xed,
                (byte)0xa1, (byte)0xda, (byte)0xd8, (byte)0x66
            }),
            new Fragment( 768, new byte[] {
                (byte)0x32, (byte)0x82, (byte)0x8f, (byte)0x91,
                (byte)0x50, (byte)0x2b, (byte)0x62, (byte)0x91, 
                (byte)0x36, (byte)0x8d, (byte)0xe8, (byte)0x08,
                (byte)0x1d, (byte)0xe3, (byte)0x6f, (byte)0xc2
            }),
            new Fragment(1008, new byte[] {
                (byte)0xf3, (byte)0xb9, (byte)0xa7, (byte)0xe3,
                (byte)0xb2, (byte)0x97, (byte)0xbf, (byte)0x9a, 
                (byte)0xd8, (byte)0x04, (byte)0x51, (byte)0x2f,
                (byte)0x90, (byte)0x63, (byte)0xef, (byte)0xf1
            }),
            new Fragment(1024, new byte[] {
                (byte)0x8e, (byte)0xcb, (byte)0x67, (byte)0xa9,
                (byte)0xba, (byte)0x1f, (byte)0x55, (byte)0xa5, 
                (byte)0xa0, (byte)0x67, (byte)0xe2, (byte)0xb0,
                (byte)0x26, (byte)0xa3, (byte)0x67, (byte)0x6f
            }),
            new Fragment(1520, new byte[] {
                (byte)0xd2, (byte)0xaa, (byte)0x90, (byte)0x2b,
                (byte)0xd4, (byte)0x2d, (byte)0x0d, (byte)0x7c, 
                (byte)0xfd, (byte)0x34, (byte)0x0c, (byte)0xd4,
                (byte)0x58, (byte)0x10, (byte)0x52, (byte)0x9f
            }),
            new Fragment(1536, new byte[] {
                (byte)0x78, (byte)0xb2, (byte)0x72, (byte)0xc9,
                (byte)0x6e, (byte)0x42, (byte)0xea, (byte)0xb4, 
                (byte)0xc6, (byte)0x0b, (byte)0xd9, (byte)0x14,
                (byte)0xe3, (byte)0x9d, (byte)0x06, (byte)0xe3
            }),
            new Fragment(2032, new byte[] {
                (byte)0xf4, (byte)0x33, (byte)0x2f, (byte)0xd3,
                (byte)0x1a, (byte)0x07, (byte)0x93, (byte)0x96, 
                (byte)0xee, (byte)0x3c, (byte)0xee, (byte)0x3f,
                (byte)0x2a, (byte)0x4f, (byte)0xf0, (byte)0x49
            }),
            new Fragment(2048, new byte[] {
                (byte)0x05, (byte)0x45, (byte)0x97, (byte)0x81,
                (byte)0xd4, (byte)0x1f, (byte)0xda, (byte)0x7f, 
                (byte)0x30, (byte)0xc1, (byte)0xbe, (byte)0x7e,
                (byte)0x12, (byte)0x46, (byte)0xc6, (byte)0x23
            }),
            new Fragment(3056, new byte[] {
                (byte)0xad, (byte)0xfd, (byte)0x38, (byte)0x68,
                (byte)0xb8, (byte)0xe5, (byte)0x14, (byte)0x85, 
                (byte)0xd5, (byte)0xe6, (byte)0x10, (byte)0x01,
                (byte)0x7e, (byte)0x3d, (byte)0xd6, (byte)0x09
            }),
            new Fragment(3072, new byte[] {
                (byte)0xad, (byte)0x26, (byte)0x58, (byte)0x1c,
                (byte)0x0c, (byte)0x5b, (byte)0xe4, (byte)0x5f, 
                (byte)0x4c, (byte)0xea, (byte)0x01, (byte)0xdb,
                (byte)0x2f, (byte)0x38, (byte)0x05, (byte)0xd5
            }),
            new Fragment(4080, new byte[] {
                (byte)0xf3, (byte)0x17, (byte)0x2c, (byte)0xef,
                (byte)0xfc, (byte)0x3b, (byte)0x3d, (byte)0x99, 
                (byte)0x7c, (byte)0x85, (byte)0xcc, (byte)0xd5,
                (byte)0xaf, (byte)0x1a, (byte)0x95, (byte)0x0c
            }),
            new Fragment(4096, new byte[] {
                (byte)0xe7, (byte)0x4b, (byte)0x0b, (byte)0x97,
                (byte)0x31, (byte)0x22, (byte)0x7f, (byte)0xd3, 
                (byte)0x7c, (byte)0x0e, (byte)0xc0, (byte)0x8a,
                (byte)0x47, (byte)0xdd, (byte)0xd8, (byte)0xb8
            }));
            if (CAPI.KeySizes.Contains(keySizes, 7))
            KnownTest(cipher, new byte[] { 
                (byte)0x19, (byte)0x10, (byte)0x83, (byte)0x32, 
                (byte)0x22, (byte)0x77, (byte)0x2a
            },
            new Fragment(  0, new byte[] {
                (byte)0xbc, (byte)0x92, (byte)0x22, (byte)0xdb,
                (byte)0xd3, (byte)0x27, (byte)0x4d, (byte)0x8f, 
                (byte)0xc6, (byte)0x6d, (byte)0x14, (byte)0xcc,
                (byte)0xbd, (byte)0xa6, (byte)0x69, (byte)0x0b
            }),
            new Fragment( 16, new byte[] {
                (byte)0x7a, (byte)0xe6, (byte)0x27, (byte)0x41,
                (byte)0x0c, (byte)0x9a, (byte)0x2b, (byte)0xe6, 
                (byte)0x93, (byte)0xdf, (byte)0x5b, (byte)0xb7,
                (byte)0x48, (byte)0x5a, (byte)0x63, (byte)0xe3
            }),
            new Fragment( 240, new byte[] {
                (byte)0x3f, (byte)0x09, (byte)0x31, (byte)0xaa,
                (byte)0x03, (byte)0xde, (byte)0xfb, (byte)0x30, 
                (byte)0x0f, (byte)0x06, (byte)0x01, (byte)0x03,
                (byte)0x82, (byte)0x6f, (byte)0x2a, (byte)0x64
            }),
            new Fragment( 256, new byte[] {
                (byte)0xbe, (byte)0xaa, (byte)0x9e, (byte)0xc8,
                (byte)0xd5, (byte)0x9b, (byte)0xb6, (byte)0x81, 
                (byte)0x29, (byte)0xf3, (byte)0x02, (byte)0x7c,
                (byte)0x96, (byte)0x36, (byte)0x11, (byte)0x81
            }),
            new Fragment( 496, new byte[] {
                (byte)0x74, (byte)0xe0, (byte)0x4d, (byte)0xb4,
                (byte)0x6d, (byte)0x28, (byte)0x64, (byte)0x8d, 
                (byte)0x7d, (byte)0xee, (byte)0x8a, (byte)0x00,
                (byte)0x64, (byte)0xb0, (byte)0x6c, (byte)0xfe
            }),
            new Fragment( 512, new byte[] {
                (byte)0x9b, (byte)0x5e, (byte)0x81, (byte)0xc6,
                (byte)0x2f, (byte)0xe0, (byte)0x23, (byte)0xc5, 
                (byte)0x5b, (byte)0xe4, (byte)0x2f, (byte)0x87,
                (byte)0xbb, (byte)0xf9, (byte)0x32, (byte)0xb8
            }),
            new Fragment( 752, new byte[] {
                (byte)0xce, (byte)0x17, (byte)0x8f, (byte)0xc1,
                (byte)0x82, (byte)0x6e, (byte)0xfe, (byte)0xcb, 
                (byte)0xc1, (byte)0x82, (byte)0xf5, (byte)0x79,
                (byte)0x99, (byte)0xa4, (byte)0x61, (byte)0x40
            }),
            new Fragment( 768, new byte[] {
                (byte)0x8b, (byte)0xdf, (byte)0x55, (byte)0xcd,
                (byte)0x55, (byte)0x06, (byte)0x1c, (byte)0x06, 
                (byte)0xdb, (byte)0xa6, (byte)0xbe, (byte)0x11,
                (byte)0xde, (byte)0x4a, (byte)0x57, (byte)0x8a
            }),
            new Fragment(1008, new byte[] {
                (byte)0x62, (byte)0x6f, (byte)0x5f, (byte)0x4d,
                (byte)0xce, (byte)0x65, (byte)0x25, (byte)0x01, 
                (byte)0xf3, (byte)0x08, (byte)0x7d, (byte)0x39,
                (byte)0xc9, (byte)0x2c, (byte)0xc3, (byte)0x49
            }),
            new Fragment(1024, new byte[] {
                (byte)0x42, (byte)0xda, (byte)0xac, (byte)0x6a,
                (byte)0x8f, (byte)0x9a, (byte)0xb9, (byte)0xa7, 
                (byte)0xfd, (byte)0x13, (byte)0x7c, (byte)0x60,
                (byte)0x37, (byte)0x82, (byte)0x56, (byte)0x82
            }),
            new Fragment(1520, new byte[] {
                (byte)0xcc, (byte)0x03, (byte)0xfd, (byte)0xb7,
                (byte)0x91, (byte)0x92, (byte)0xa2, (byte)0x07, 
                (byte)0x31, (byte)0x2f, (byte)0x53, (byte)0xf5,
                (byte)0xd4, (byte)0xdc, (byte)0x33, (byte)0xd9
            }),
            new Fragment(1536, new byte[] {
                (byte)0xf7, (byte)0x0f, (byte)0x14, (byte)0x12,
                (byte)0x2a, (byte)0x1c, (byte)0x98, (byte)0xa3, 
                (byte)0x15, (byte)0x5d, (byte)0x28, (byte)0xb8,
                (byte)0xa0, (byte)0xa8, (byte)0xa4, (byte)0x1d
            }),
            new Fragment(2032, new byte[] {
                (byte)0x2a, (byte)0x3a, (byte)0x30, (byte)0x7a,
                (byte)0xb2, (byte)0x70, (byte)0x8a, (byte)0x9c, 
                (byte)0x00, (byte)0xfe, (byte)0x0b, (byte)0x42,
                (byte)0xf9, (byte)0xc2, (byte)0xd6, (byte)0xa1
            }),
            new Fragment(2048, new byte[] {
                (byte)0x86, (byte)0x26, (byte)0x17, (byte)0x62,
                (byte)0x7d, (byte)0x22, (byte)0x61, (byte)0xea, 
                (byte)0xb0, (byte)0xb1, (byte)0x24, (byte)0x65,
                (byte)0x97, (byte)0xca, (byte)0x0a, (byte)0xe9
            }),
            new Fragment(3056, new byte[] {
                (byte)0x55, (byte)0xf8, (byte)0x77, (byte)0xce,
                (byte)0x4f, (byte)0x2e, (byte)0x1d, (byte)0xdb, 
                (byte)0xbf, (byte)0x8e, (byte)0x13, (byte)0xe2,
                (byte)0xcd, (byte)0xe0, (byte)0xfd, (byte)0xc8
            }),
            new Fragment(3072, new byte[] {
                (byte)0x1b, (byte)0x15, (byte)0x56, (byte)0xcb,
                (byte)0x93, (byte)0x5f, (byte)0x17, (byte)0x33, 
                (byte)0x37, (byte)0x70, (byte)0x5f, (byte)0xbb,
                (byte)0x5d, (byte)0x50, (byte)0x1f, (byte)0xc1
            }),
            new Fragment(4080, new byte[] {
                (byte)0xec, (byte)0xd0, (byte)0xe9, (byte)0x66,
                (byte)0x02, (byte)0xbe, (byte)0x7f, (byte)0x8d, 
                (byte)0x50, (byte)0x92, (byte)0x81, (byte)0x6c,
                (byte)0xcc, (byte)0xf2, (byte)0xc2, (byte)0xe9
            }),
            new Fragment(4096, new byte[] {
                (byte)0x02, (byte)0x78, (byte)0x81, (byte)0xfa,
                (byte)0xb4, (byte)0x99, (byte)0x3a, (byte)0x1c, 
                (byte)0x26, (byte)0x20, (byte)0x24, (byte)0xa9,
                (byte)0x4f, (byte)0xff, (byte)0x3f, (byte)0x61
            }));
            if (CAPI.KeySizes.Contains(keySizes, 8))
            KnownTest(cipher, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08
            },
            new Fragment(  0, new byte[] {
                (byte)0x97, (byte)0xab, (byte)0x8a, (byte)0x1b,
                (byte)0xf0, (byte)0xaf, (byte)0xb9, (byte)0x61, 
                (byte)0x32, (byte)0xf2, (byte)0xf6, (byte)0x72,
                (byte)0x58, (byte)0xda, (byte)0x15, (byte)0xa8
            }),
            new Fragment( 16, new byte[] {
                (byte)0x82, (byte)0x63, (byte)0xef, (byte)0xdb,
                (byte)0x45, (byte)0xc4, (byte)0xa1, (byte)0x86, 
                (byte)0x84, (byte)0xef, (byte)0x87, (byte)0xe6,
                (byte)0xb1, (byte)0x9e, (byte)0x5b, (byte)0x09
            }),
            new Fragment( 240, new byte[] {
                (byte)0x96, (byte)0x36, (byte)0xeb, (byte)0xc9,
                (byte)0x84, (byte)0x19, (byte)0x26, (byte)0xf4, 
                (byte)0xf7, (byte)0xd1, (byte)0xf3, (byte)0x62,
                (byte)0xbd, (byte)0xdf, (byte)0x6e, (byte)0x18
            }),
            new Fragment( 256, new byte[] {
                (byte)0xd0, (byte)0xa9, (byte)0x90, (byte)0xff,
                (byte)0x2c, (byte)0x05, (byte)0xfe, (byte)0xf5, 
                (byte)0xb9, (byte)0x03, (byte)0x73, (byte)0xc9,
                (byte)0xff, (byte)0x4b, (byte)0x87, (byte)0x0a
            }),
            new Fragment( 496, new byte[] {
                (byte)0x73, (byte)0x23, (byte)0x9f, (byte)0x1d,
                (byte)0xb7, (byte)0xf4, (byte)0x1d, (byte)0x80, 
                (byte)0xb6, (byte)0x43, (byte)0xc0, (byte)0xc5,
                (byte)0x25, (byte)0x18, (byte)0xec, (byte)0x63
            }),
            new Fragment( 512, new byte[] {
                (byte)0x16, (byte)0x3b, (byte)0x31, (byte)0x99,
                (byte)0x23, (byte)0xa6, (byte)0xbd, (byte)0xb4, 
                (byte)0x52, (byte)0x7c, (byte)0x62, (byte)0x61,
                (byte)0x26, (byte)0x70, (byte)0x3c, (byte)0x0f
            }),
            new Fragment( 752, new byte[] {
                (byte)0x49, (byte)0xd6, (byte)0xc8, (byte)0xaf,
                (byte)0x0f, (byte)0x97, (byte)0x14, (byte)0x4a, 
                (byte)0x87, (byte)0xdf, (byte)0x21, (byte)0xd9,
                (byte)0x14, (byte)0x72, (byte)0xf9, (byte)0x66
            }),
            new Fragment( 768, new byte[] {
                (byte)0x44, (byte)0x17, (byte)0x3a, (byte)0x10,
                (byte)0x3b, (byte)0x66, (byte)0x16, (byte)0xc5, 
                (byte)0xd5, (byte)0xad, (byte)0x1c, (byte)0xee,
                (byte)0x40, (byte)0xc8, (byte)0x63, (byte)0xd0
            }),
            new Fragment(1008, new byte[] {
                (byte)0x27, (byte)0x3c, (byte)0x9c, (byte)0x4b,
                (byte)0x27, (byte)0xf3, (byte)0x22, (byte)0xe4, 
                (byte)0xe7, (byte)0x16, (byte)0xef, (byte)0x53,
                (byte)0xa4, (byte)0x7d, (byte)0xe7, (byte)0xa4
            }),
            new Fragment(1024, new byte[] {
                (byte)0xc6, (byte)0xd0, (byte)0xe7, (byte)0xb2,
                (byte)0x26, (byte)0x25, (byte)0x9f, (byte)0xa9, 
                (byte)0x02, (byte)0x34, (byte)0x90, (byte)0xb2,
                (byte)0x61, (byte)0x67, (byte)0xad, (byte)0x1d
            }),
            new Fragment(1520, new byte[] {
                (byte)0x1f, (byte)0xe8, (byte)0x98, (byte)0x67,
                (byte)0x13, (byte)0xf0, (byte)0x7c, (byte)0x3d, 
                (byte)0x9a, (byte)0xe1, (byte)0xc1, (byte)0x63,
                (byte)0xff, (byte)0x8c, (byte)0xf9, (byte)0xd3
            }),
            new Fragment(1536, new byte[] {
                (byte)0x83, (byte)0x69, (byte)0xe1, (byte)0xa9,
                (byte)0x65, (byte)0x61, (byte)0x0b, (byte)0xe8, 
                (byte)0x87, (byte)0xfb, (byte)0xd0, (byte)0xc7,
                (byte)0x91, (byte)0x62, (byte)0xaa, (byte)0xfb
            }),
            new Fragment(2032, new byte[] {
                (byte)0x0a, (byte)0x01, (byte)0x27, (byte)0xab,
                (byte)0xb4, (byte)0x44, (byte)0x84, (byte)0xb9, 
                (byte)0xfb, (byte)0xef, (byte)0x5a, (byte)0xbc,
                (byte)0xae, (byte)0x1b, (byte)0x57, (byte)0x9f
            }),
            new Fragment(2048, new byte[] {
                (byte)0xc2, (byte)0xcd, (byte)0xad, (byte)0xc6,
                (byte)0x40, (byte)0x2e, (byte)0x8e, (byte)0xe8, 
                (byte)0x66, (byte)0xe1, (byte)0xf3, (byte)0x7b,
                (byte)0xdb, (byte)0x47, (byte)0xe4, (byte)0x2c
            }),
            new Fragment(3056, new byte[] {
                (byte)0x26, (byte)0xb5, (byte)0x1e, (byte)0xa3,
                (byte)0x7d, (byte)0xf8, (byte)0xe1, (byte)0xd6, 
                (byte)0xf7, (byte)0x6f, (byte)0xc3, (byte)0xb6,
                (byte)0x6a, (byte)0x74, (byte)0x29, (byte)0xb3
            }),
            new Fragment(3072, new byte[] {
                (byte)0xbc, (byte)0x76, (byte)0x83, (byte)0x20,
                (byte)0x5d, (byte)0x4f, (byte)0x44, (byte)0x3d, 
                (byte)0xc1, (byte)0xf2, (byte)0x9d, (byte)0xda,
                (byte)0x33, (byte)0x15, (byte)0xc8, (byte)0x7b
            }),
            new Fragment(4080, new byte[] {
                (byte)0xd5, (byte)0xfa, (byte)0x5a, (byte)0x34,
                (byte)0x69, (byte)0xd2, (byte)0x9a, (byte)0xaa, 
                (byte)0xf8, (byte)0x3d, (byte)0x23, (byte)0x58,
                (byte)0x9d, (byte)0xb8, (byte)0xc8, (byte)0x5b
            }),
            new Fragment(4096, new byte[] {
                (byte)0x3f, (byte)0xb4, (byte)0x6e, (byte)0x2c,
                (byte)0x8f, (byte)0x0f, (byte)0x06, (byte)0x8e, 
                (byte)0xdc, (byte)0xe8, (byte)0xcd, (byte)0xcd,
                (byte)0x7d, (byte)0xfc, (byte)0x58, (byte)0x62
            }));
            if (CAPI.KeySizes.Contains(keySizes, 8))
            KnownTest(cipher, new byte[] { 
                (byte)0x64, (byte)0x19, (byte)0x10, (byte)0x83, 
                (byte)0x32, (byte)0x22, (byte)0x77, (byte)0x2a
            },
            new Fragment(  0, new byte[] {
                (byte)0xbb, (byte)0xf6, (byte)0x09, (byte)0xde,
                (byte)0x94, (byte)0x13, (byte)0x17, (byte)0x2d, 
                (byte)0x07, (byte)0x66, (byte)0x0c, (byte)0xb6,
                (byte)0x80, (byte)0x71, (byte)0x69, (byte)0x26
            }),
            new Fragment( 16, new byte[] {
                (byte)0x46, (byte)0x10, (byte)0x1a, (byte)0x6d,
                (byte)0xab, (byte)0x43, (byte)0x11, (byte)0x5d, 
                (byte)0x6c, (byte)0x52, (byte)0x2b, (byte)0x4f,
                (byte)0xe9, (byte)0x36, (byte)0x04, (byte)0xa9
            }),
            new Fragment( 240, new byte[] {
                (byte)0xcb, (byte)0xe1, (byte)0xff, (byte)0xf2,
                (byte)0x1c, (byte)0x96, (byte)0xf3, (byte)0xee, 
                (byte)0xf6, (byte)0x1e, (byte)0x8f, (byte)0xe0,
                (byte)0x54, (byte)0x2c, (byte)0xbd, (byte)0xf0
            }),
            new Fragment( 256, new byte[] {
                (byte)0x34, (byte)0x79, (byte)0x38, (byte)0xbf,
                (byte)0xfa, (byte)0x40, (byte)0x09, (byte)0xc5, 
                (byte)0x12, (byte)0xcf, (byte)0xb4, (byte)0x03,
                (byte)0x4b, (byte)0x0d, (byte)0xd1, (byte)0xa7
            }),
            new Fragment( 496, new byte[] {
                (byte)0x78, (byte)0x67, (byte)0xa7, (byte)0x86,
                (byte)0xd0, (byte)0x0a, (byte)0x71, (byte)0x47, 
                (byte)0x90, (byte)0x4d, (byte)0x76, (byte)0xdd,
                (byte)0xf1, (byte)0xe5, (byte)0x20, (byte)0xe3
            }),
            new Fragment( 512, new byte[] {
                (byte)0x8d, (byte)0x3e, (byte)0x9e, (byte)0x1c,
                (byte)0xae, (byte)0xfc, (byte)0xcc, (byte)0xb3, 
                (byte)0xfb, (byte)0xf8, (byte)0xd1, (byte)0x8f,
                (byte)0x64, (byte)0x12, (byte)0x0b, (byte)0x32
            }),
            new Fragment( 752, new byte[] {
                (byte)0x94, (byte)0x23, (byte)0x37, (byte)0xf8,
                (byte)0xfd, (byte)0x76, (byte)0xf0, (byte)0xfa, 
                (byte)0xe8, (byte)0xc5, (byte)0x2d, (byte)0x79,
                (byte)0x54, (byte)0x81, (byte)0x06, (byte)0x72
            }),
            new Fragment( 768, new byte[] {
                (byte)0xb8, (byte)0x54, (byte)0x8c, (byte)0x10,
                (byte)0xf5, (byte)0x16, (byte)0x67, (byte)0xf6, 
                (byte)0xe6, (byte)0x0e, (byte)0x18, (byte)0x2f,
                (byte)0xa1, (byte)0x9b, (byte)0x30, (byte)0xf7
            }),
            new Fragment(1008, new byte[] {
                (byte)0x02, (byte)0x11, (byte)0xc7, (byte)0xc6,
                (byte)0x19, (byte)0x0c, (byte)0x9e, (byte)0xfd, 
                (byte)0x12, (byte)0x37, (byte)0xc3, (byte)0x4c,
                (byte)0x8f, (byte)0x2e, (byte)0x06, (byte)0xc4
            }),
            new Fragment(1024, new byte[] {
                (byte)0xbd, (byte)0xa6, (byte)0x4f, (byte)0x65,
                (byte)0x27, (byte)0x6d, (byte)0x2a, (byte)0xac, 
                (byte)0xb8, (byte)0xf9, (byte)0x02, (byte)0x12,
                (byte)0x20, (byte)0x3a, (byte)0x80, (byte)0x8e
            }),
            new Fragment(1520, new byte[] {
                (byte)0xbd, (byte)0x38, (byte)0x20, (byte)0xf7,
                (byte)0x32, (byte)0xff, (byte)0xb5, (byte)0x3e, 
                (byte)0xc1, (byte)0x93, (byte)0xe7, (byte)0x9d,
                (byte)0x33, (byte)0xe2, (byte)0x7c, (byte)0x73
            }),
            new Fragment(1536, new byte[] {
                (byte)0xd0, (byte)0x16, (byte)0x86, (byte)0x16,
                (byte)0x86, (byte)0x19, (byte)0x07, (byte)0xd4, 
                (byte)0x82, (byte)0xe3, (byte)0x6c, (byte)0xda,
                (byte)0xc8, (byte)0xcf, (byte)0x57, (byte)0x49
            }),
            new Fragment(2032, new byte[] {
                (byte)0x97, (byte)0xb0, (byte)0xf0, (byte)0xf2,
                (byte)0x24, (byte)0xb2, (byte)0xd2, (byte)0x31, 
                (byte)0x71, (byte)0x14, (byte)0x80, (byte)0x8f,
                (byte)0xb0, (byte)0x3a, (byte)0xf7, (byte)0xa0
            }),
            new Fragment(2048, new byte[] {
                (byte)0xe5, (byte)0x96, (byte)0x16, (byte)0xe4,
                (byte)0x69, (byte)0x78, (byte)0x79, (byte)0x39, 
                (byte)0xa0, (byte)0x63, (byte)0xce, (byte)0xea,
                (byte)0x9a, (byte)0xf9, (byte)0x56, (byte)0xd1
            }),
            new Fragment(3056, new byte[] {
                (byte)0xc4, (byte)0x7e, (byte)0x0d, (byte)0xc1,
                (byte)0x66, (byte)0x09, (byte)0x19, (byte)0xc1, 
                (byte)0x11, (byte)0x01, (byte)0x20, (byte)0x8f,
                (byte)0x9e, (byte)0x69, (byte)0xaa, (byte)0x1f
            }),
            new Fragment(3072, new byte[] {
                (byte)0x5a, (byte)0xe4, (byte)0xf1, (byte)0x28,
                (byte)0x96, (byte)0xb8, (byte)0x37, (byte)0x9a, 
                (byte)0x2a, (byte)0xad, (byte)0x89, (byte)0xb5,
                (byte)0xb5, (byte)0x53, (byte)0xd6, (byte)0xb0
            }),
            new Fragment(4080, new byte[] {
                (byte)0x6b, (byte)0x6b, (byte)0x09, (byte)0x8d,
                (byte)0x0c, (byte)0x29, (byte)0x3b, (byte)0xc2, 
                (byte)0x99, (byte)0x3d, (byte)0x80, (byte)0xbf,
                (byte)0x05, (byte)0x18, (byte)0xb6, (byte)0xd9
            }),
            new Fragment(4096, new byte[] {
                (byte)0x81, (byte)0x70, (byte)0xcc, (byte)0x3c,
                (byte)0xcd, (byte)0x92, (byte)0xa6, (byte)0x98, 
                (byte)0x62, (byte)0x1b, (byte)0x93, (byte)0x9d,
                (byte)0xd3, (byte)0x8f, (byte)0xe7, (byte)0xb9
            }));
            if (CAPI.KeySizes.Contains(keySizes, 10))
            KnownTest(cipher, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                (byte)0x09, (byte)0x0a
            },
            new Fragment(  0, new byte[] {
                (byte)0xed, (byte)0xe3, (byte)0xb0, (byte)0x46,
                (byte)0x43, (byte)0xe5, (byte)0x86, (byte)0xcc, 
                (byte)0x90, (byte)0x7d, (byte)0xc2, (byte)0x18,
                (byte)0x51, (byte)0x70, (byte)0x99, (byte)0x02
            }),
            new Fragment( 16, new byte[] {
                (byte)0x03, (byte)0x51, (byte)0x6b, (byte)0xa7,
                (byte)0x8f, (byte)0x41, (byte)0x3b, (byte)0xeb, 
                (byte)0x22, (byte)0x3a, (byte)0xa5, (byte)0xd4,
                (byte)0xd2, (byte)0xdf, (byte)0x67, (byte)0x11
            }),
            new Fragment( 240, new byte[] {
                (byte)0x3c, (byte)0xfd, (byte)0x6c, (byte)0xb5,
                (byte)0x8e, (byte)0xe0, (byte)0xfd, (byte)0xde, 
                (byte)0x64, (byte)0x01, (byte)0x76, (byte)0xad,
                (byte)0x00, (byte)0x00, (byte)0x04, (byte)0x4d
            }),
            new Fragment( 256, new byte[] {
                (byte)0x48, (byte)0x53, (byte)0x2b, (byte)0x21,
                (byte)0xfb, (byte)0x60, (byte)0x79, (byte)0xc9, 
                (byte)0x11, (byte)0x4c, (byte)0x0f, (byte)0xfd,
                (byte)0x9c, (byte)0x04, (byte)0xa1, (byte)0xad
            }),
            new Fragment( 496, new byte[] {
                (byte)0x3e, (byte)0x8c, (byte)0xea, (byte)0x98,
                (byte)0x01, (byte)0x71, (byte)0x09, (byte)0x97, 
                (byte)0x90, (byte)0x84, (byte)0xb1, (byte)0xef,
                (byte)0x92, (byte)0xf9, (byte)0x9d, (byte)0x86
            }),
            new Fragment( 512, new byte[] {
                (byte)0xe2, (byte)0x0f, (byte)0xb4, (byte)0x9b,
                (byte)0xdb, (byte)0x33, (byte)0x7e, (byte)0xe4, 
                (byte)0x8b, (byte)0x8d, (byte)0x8d, (byte)0xc0,
                (byte)0xf4, (byte)0xaf, (byte)0xef, (byte)0xfe
            }),
            new Fragment( 752, new byte[] {
                (byte)0x5c, (byte)0x25, (byte)0x21, (byte)0xea,
                (byte)0xcd, (byte)0x79, (byte)0x66, (byte)0xf1, 
                (byte)0x5e, (byte)0x05, (byte)0x65, (byte)0x44,
                (byte)0xbe, (byte)0xa0, (byte)0xd3, (byte)0x15
            }),
            new Fragment( 768, new byte[] {
                (byte)0xe0, (byte)0x67, (byte)0xa7, (byte)0x03,
                (byte)0x19, (byte)0x31, (byte)0xa2, (byte)0x46, 
                (byte)0xa6, (byte)0xc3, (byte)0x87, (byte)0x5d,
                (byte)0x2f, (byte)0x67, (byte)0x8a, (byte)0xcb
            }),
            new Fragment(1008, new byte[] {
                (byte)0xa6, (byte)0x4f, (byte)0x70, (byte)0xaf,
                (byte)0x88, (byte)0xae, (byte)0x56, (byte)0xb6, 
                (byte)0xf8, (byte)0x75, (byte)0x81, (byte)0xc0,
                (byte)0xe2, (byte)0x3e, (byte)0x6b, (byte)0x08
            }),
            new Fragment(1024, new byte[] {
                (byte)0xf4, (byte)0x49, (byte)0x03, (byte)0x1d,
                (byte)0xe3, (byte)0x12, (byte)0x81, (byte)0x4e, 
                (byte)0xc6, (byte)0xf3, (byte)0x19, (byte)0x29,
                (byte)0x1f, (byte)0x4a, (byte)0x05, (byte)0x16
            }),
            new Fragment(1520, new byte[] {
                (byte)0xbd, (byte)0xae, (byte)0x85, (byte)0x92,
                (byte)0x4b, (byte)0x3c, (byte)0xb1, (byte)0xd0, 
                (byte)0xa2, (byte)0xe3, (byte)0x3a, (byte)0x30,
                (byte)0xc6, (byte)0xd7, (byte)0x95, (byte)0x99
            }),
            new Fragment(1536, new byte[] {
                (byte)0x8a, (byte)0x0f, (byte)0xed, (byte)0xdb,
                (byte)0xac, (byte)0x86, (byte)0x5a, (byte)0x09, 
                (byte)0xbc, (byte)0xd1, (byte)0x27, (byte)0xfb,
                (byte)0x56, (byte)0x2e, (byte)0xd6, (byte)0x0a
            }),
            new Fragment(2032, new byte[] {
                (byte)0xb5, (byte)0x5a, (byte)0x0a, (byte)0x5b,
                (byte)0x51, (byte)0xa1, (byte)0x2a, (byte)0x8b, 
                (byte)0xe3, (byte)0x48, (byte)0x99, (byte)0xc3,
                (byte)0xe0, (byte)0x47, (byte)0x51, (byte)0x1a
            }),
            new Fragment(2048, new byte[] {
                (byte)0xd9, (byte)0xa0, (byte)0x9c, (byte)0xea,
                (byte)0x3c, (byte)0xe7, (byte)0x5f, (byte)0xe3, 
                (byte)0x96, (byte)0x98, (byte)0x07, (byte)0x03,
                (byte)0x17, (byte)0xa7, (byte)0x13, (byte)0x39
            }),
            new Fragment(3056, new byte[] {
                (byte)0x55, (byte)0x22, (byte)0x25, (byte)0xed,
                (byte)0x11, (byte)0x77, (byte)0xf4, (byte)0x45, 
                (byte)0x84, (byte)0xac, (byte)0x8c, (byte)0xfa,
                (byte)0x6c, (byte)0x4e, (byte)0xb5, (byte)0xfc
            }),
            new Fragment(3072, new byte[] {
                (byte)0x7e, (byte)0x82, (byte)0xcb, (byte)0xab,
                (byte)0xfc, (byte)0x95, (byte)0x38, (byte)0x1b, 
                (byte)0x08, (byte)0x09, (byte)0x98, (byte)0x44,
                (byte)0x21, (byte)0x29, (byte)0xc2, (byte)0xf8
            }),
            new Fragment(4080, new byte[] {
                (byte)0x1f, (byte)0x13, (byte)0x5e, (byte)0xd1,
                (byte)0x4c, (byte)0xe6, (byte)0x0a, (byte)0x91, 
                (byte)0x36, (byte)0x9d, (byte)0x23, (byte)0x22,
                (byte)0xbe, (byte)0xf2, (byte)0x5e, (byte)0x3c
            }),
            new Fragment(4096, new byte[] {
                (byte)0x08, (byte)0xb6, (byte)0xbe, (byte)0x45,
                (byte)0x12, (byte)0x4a, (byte)0x43, (byte)0xe2, 
                (byte)0xeb, (byte)0x77, (byte)0x95, (byte)0x3f,
                (byte)0x84, (byte)0xdc, (byte)0x85, (byte)0x53
            }));
            if (CAPI.KeySizes.Contains(keySizes, 10))
            KnownTest(cipher, new byte[] { 
                (byte)0x8b, (byte)0x37, (byte)0x64, (byte)0x19, 
                (byte)0x10, (byte)0x83, (byte)0x32, (byte)0x22, 
                (byte)0x77, (byte)0x2a
            },
            new Fragment(  0, new byte[] {
                (byte)0xab, (byte)0x65, (byte)0xc2, (byte)0x6e,
                (byte)0xdd, (byte)0xb2, (byte)0x87, (byte)0x60, 
                (byte)0x0d, (byte)0xb2, (byte)0xfd, (byte)0xa1,
                (byte)0x0d, (byte)0x1e, (byte)0x60, (byte)0x5c
            }),
            new Fragment( 16, new byte[] {
                (byte)0xbb, (byte)0x75, (byte)0x90, (byte)0x10,
                (byte)0xc2, (byte)0x96, (byte)0x58, (byte)0xf2, 
                (byte)0xc7, (byte)0x2d, (byte)0x93, (byte)0xa2,
                (byte)0xd1, (byte)0x6d, (byte)0x29, (byte)0x30
            }),
            new Fragment( 240, new byte[] {
                (byte)0xb9, (byte)0x01, (byte)0xe8, (byte)0x03,
                (byte)0x6e, (byte)0xd1, (byte)0xc3, (byte)0x83, 
                (byte)0xcd, (byte)0x3c, (byte)0x4c, (byte)0x4d,
                (byte)0xd0, (byte)0xa6, (byte)0xab, (byte)0x05
            }),
            new Fragment( 256, new byte[] {
                (byte)0x3d, (byte)0x25, (byte)0xce, (byte)0x49,
                (byte)0x22, (byte)0x92, (byte)0x4c, (byte)0x55, 
                (byte)0xf0, (byte)0x64, (byte)0x94, (byte)0x33,
                (byte)0x53, (byte)0xd7, (byte)0x8a, (byte)0x6c
            }),
            new Fragment( 496, new byte[] {
                (byte)0x12, (byte)0xc1, (byte)0xaa, (byte)0x44,
                (byte)0xbb, (byte)0xf8, (byte)0x7e, (byte)0x75, 
                (byte)0xe6, (byte)0x11, (byte)0xf6, (byte)0x9b,
                (byte)0x2c, (byte)0x38, (byte)0xf4, (byte)0x9b
            }),
            new Fragment( 512, new byte[] {
                (byte)0x28, (byte)0xf2, (byte)0xb3, (byte)0x43,
                (byte)0x4b, (byte)0x65, (byte)0xc0, (byte)0x98, 
                (byte)0x77, (byte)0x47, (byte)0x00, (byte)0x44,
                (byte)0xc6, (byte)0xea, (byte)0x17, (byte)0x0d
            }),
            new Fragment( 752, new byte[] {
                (byte)0xbd, (byte)0x9e, (byte)0xf8, (byte)0x22,
                (byte)0xde, (byte)0x52, (byte)0x88, (byte)0x19, 
                (byte)0x61, (byte)0x34, (byte)0xcf, (byte)0x8a,
                (byte)0xf7, (byte)0x83, (byte)0x93, (byte)0x04
            }),
            new Fragment( 768, new byte[] {
                (byte)0x67, (byte)0x55, (byte)0x9c, (byte)0x23,
                (byte)0xf0, (byte)0x52, (byte)0x15, (byte)0x84, 
                (byte)0x70, (byte)0xa2, (byte)0x96, (byte)0xf7,
                (byte)0x25, (byte)0x73, (byte)0x5a, (byte)0x32
            }),
            new Fragment(1008, new byte[] {
                (byte)0x8b, (byte)0xab, (byte)0x26, (byte)0xfb,
                (byte)0xc2, (byte)0xc1, (byte)0x2b, (byte)0x0f, 
                (byte)0x13, (byte)0xe2, (byte)0xab, (byte)0x18,
                (byte)0x5e, (byte)0xab, (byte)0xf2, (byte)0x41
            }),
            new Fragment(1024, new byte[] {
                (byte)0x31, (byte)0x18, (byte)0x5a, (byte)0x6d,
                (byte)0x69, (byte)0x6f, (byte)0x0c, (byte)0xfa, 
                (byte)0x9b, (byte)0x42, (byte)0x80, (byte)0x8b,
                (byte)0x38, (byte)0xe1, (byte)0x32, (byte)0xa2
            }),
            new Fragment(1520, new byte[] {
                (byte)0x56, (byte)0x4d, (byte)0x3d, (byte)0xae,
                (byte)0x18, (byte)0x3c, (byte)0x52, (byte)0x34, 
                (byte)0xc8, (byte)0xaf, (byte)0x1e, (byte)0x51,
                (byte)0x06, (byte)0x1c, (byte)0x44, (byte)0xb5
            }),
            new Fragment(1536, new byte[] {
                (byte)0x3c, (byte)0x07, (byte)0x78, (byte)0xa7,
                (byte)0xb5, (byte)0xf7, (byte)0x2d, (byte)0x3c, 
                (byte)0x23, (byte)0xa3, (byte)0x13, (byte)0x5c,
                (byte)0x7d, (byte)0x67, (byte)0xb9, (byte)0xf4
            }),
            new Fragment(2032, new byte[] {
                (byte)0xf3, (byte)0x43, (byte)0x69, (byte)0x89,
                (byte)0x0f, (byte)0xcf, (byte)0x16, (byte)0xfb, 
                (byte)0x51, (byte)0x7d, (byte)0xca, (byte)0xae,
                (byte)0x44, (byte)0x63, (byte)0xb2, (byte)0xdd
            }),
            new Fragment(2048, new byte[] {
                (byte)0x02, (byte)0xf3, (byte)0x1c, (byte)0x81,
                (byte)0xe8, (byte)0x20, (byte)0x07, (byte)0x31, 
                (byte)0xb8, (byte)0x99, (byte)0xb0, (byte)0x28,
                (byte)0xe7, (byte)0x91, (byte)0xbf, (byte)0xa7
            }),
            new Fragment(3056, new byte[] {
                (byte)0x72, (byte)0xda, (byte)0x64, (byte)0x62,
                (byte)0x83, (byte)0x22, (byte)0x8c, (byte)0x14, 
                (byte)0x30, (byte)0x08, (byte)0x53, (byte)0x70,
                (byte)0x17, (byte)0x95, (byte)0x61, (byte)0x6f
            }),
            new Fragment(3072, new byte[] {
                (byte)0x4e, (byte)0x0a, (byte)0x8c, (byte)0x6f,
                (byte)0x79, (byte)0x34, (byte)0xa7, (byte)0x88, 
                (byte)0xe2, (byte)0x26, (byte)0x5e, (byte)0x81,
                (byte)0xd6, (byte)0xd0, (byte)0xc8, (byte)0xf4
            }),
            new Fragment(4080, new byte[] {
                (byte)0x43, (byte)0x8d, (byte)0xd5, (byte)0xea,
                (byte)0xfe, (byte)0xa0, (byte)0x11, (byte)0x1b, 
                (byte)0x6f, (byte)0x36, (byte)0xb4, (byte)0xb9,
                (byte)0x38, (byte)0xda, (byte)0x2a, (byte)0x68
            }),
            new Fragment(4096, new byte[] {
                (byte)0x5f, (byte)0x6b, (byte)0xfc, (byte)0x73,
                (byte)0x81, (byte)0x58, (byte)0x74, (byte)0xd9, 
                (byte)0x71, (byte)0x00, (byte)0xf0, (byte)0x86,
                (byte)0x97, (byte)0x93, (byte)0x57, (byte)0xd8
            }));
            if (CAPI.KeySizes.Contains(keySizes, 16))
            KnownTest(cipher, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10
            },
            new Fragment(  0, new byte[] {
                (byte)0x9a, (byte)0xc7, (byte)0xcc, (byte)0x9a,
                (byte)0x60, (byte)0x9d, (byte)0x1e, (byte)0xf7, 
                (byte)0xb2, (byte)0x93, (byte)0x28, (byte)0x99,
                (byte)0xcd, (byte)0xe4, (byte)0x1b, (byte)0x97
            }),
            new Fragment( 16, new byte[] {
                (byte)0x52, (byte)0x48, (byte)0xc4, (byte)0x95,
                (byte)0x90, (byte)0x14, (byte)0x12, (byte)0x6a, 
                (byte)0x6e, (byte)0x8a, (byte)0x84, (byte)0xf1,
                (byte)0x1d, (byte)0x1a, (byte)0x9e, (byte)0x1c
            }),
            new Fragment( 240, new byte[] {
                (byte)0x06, (byte)0x59, (byte)0x02, (byte)0xe4,
                (byte)0xb6, (byte)0x20, (byte)0xf6, (byte)0xcc, 
                (byte)0x36, (byte)0xc8, (byte)0x58, (byte)0x9f,
                (byte)0x66, (byte)0x43, (byte)0x2f, (byte)0x2b
            }),
            new Fragment( 256, new byte[] {
                (byte)0xd3, (byte)0x9d, (byte)0x56, (byte)0x6b,
                (byte)0xc6, (byte)0xbc, (byte)0xe3, (byte)0x01, 
                (byte)0x07, (byte)0x68, (byte)0x15, (byte)0x15,
                (byte)0x49, (byte)0xf3, (byte)0x87, (byte)0x3f
            }),
            new Fragment( 496, new byte[] {
                (byte)0xb6, (byte)0xd1, (byte)0xe6, (byte)0xc4,
                (byte)0xa5, (byte)0xe4, (byte)0x77, (byte)0x1c, 
                (byte)0xad, (byte)0x79, (byte)0x53, (byte)0x8d,
                (byte)0xf2, (byte)0x95, (byte)0xfb, (byte)0x11
            }),
            new Fragment( 512, new byte[] {
                (byte)0xc6, (byte)0x8c, (byte)0x1d, (byte)0x5c,
                (byte)0x55, (byte)0x9a, (byte)0x97, (byte)0x41, 
                (byte)0x23, (byte)0xdf, (byte)0x1d, (byte)0xbc,
                (byte)0x52, (byte)0xa4, (byte)0x3b, (byte)0x89
            }),
            new Fragment( 752, new byte[] {
                (byte)0xc5, (byte)0xec, (byte)0xf8, (byte)0x8d,
                (byte)0xe8, (byte)0x97, (byte)0xfd, (byte)0x57, 
                (byte)0xfe, (byte)0xd3, (byte)0x01, (byte)0x70,
                (byte)0x1b, (byte)0x82, (byte)0xa2, (byte)0x59
            }),
            new Fragment( 768, new byte[] {
                (byte)0xec, (byte)0xcb, (byte)0xe1, (byte)0x3d,
                (byte)0xe1, (byte)0xfc, (byte)0xc9, (byte)0x1c, 
                (byte)0x11, (byte)0xa0, (byte)0xb2, (byte)0x6c,
                (byte)0x0b, (byte)0xc8, (byte)0xfa, (byte)0x4d
            }),
            new Fragment(1008, new byte[] {
                (byte)0xe7, (byte)0xa7, (byte)0x25, (byte)0x74,
                (byte)0xf8, (byte)0x78, (byte)0x2a, (byte)0xe2, 
                (byte)0x6a, (byte)0xab, (byte)0xcf, (byte)0x9e,
                (byte)0xbc, (byte)0xd6, (byte)0x60, (byte)0x65
            }),
            new Fragment(1024, new byte[] {
                (byte)0xbd, (byte)0xf0, (byte)0x32, (byte)0x4e,
                (byte)0x60, (byte)0x83, (byte)0xdc, (byte)0xc6, 
                (byte)0xd3, (byte)0xce, (byte)0xdd, (byte)0x3c,
                (byte)0xa8, (byte)0xc5, (byte)0x3c, (byte)0x16
            }),
            new Fragment(1520, new byte[] {
                (byte)0xb4, (byte)0x01, (byte)0x10, (byte)0xc4,
                (byte)0x19, (byte)0x0b, (byte)0x56, (byte)0x22, 
                (byte)0xa9, (byte)0x61, (byte)0x16, (byte)0xb0,
                (byte)0x01, (byte)0x7e, (byte)0xd2, (byte)0x97
            }),
            new Fragment(1536, new byte[] {
                (byte)0xff, (byte)0xa0, (byte)0xb5, (byte)0x14,
                (byte)0x64, (byte)0x7e, (byte)0xc0, (byte)0x4f, 
                (byte)0x63, (byte)0x06, (byte)0xb8, (byte)0x92,
                (byte)0xae, (byte)0x66, (byte)0x11, (byte)0x81
            }),
            new Fragment(2032, new byte[] {
                (byte)0xd0, (byte)0x3d, (byte)0x1b, (byte)0xc0,
                (byte)0x3c, (byte)0xd3, (byte)0x3d, (byte)0x70, 
                (byte)0xdf, (byte)0xf9, (byte)0xfa, (byte)0x5d,
                (byte)0x71, (byte)0x96, (byte)0x3e, (byte)0xbd
            }),
            new Fragment(2048, new byte[] {
                (byte)0x8a, (byte)0x44, (byte)0x12, (byte)0x64,
                (byte)0x11, (byte)0xea, (byte)0xa7, (byte)0x8b, 
                (byte)0xd5, (byte)0x1e, (byte)0x8d, (byte)0x87,
                (byte)0xa8, (byte)0x87, (byte)0x9b, (byte)0xf5
            }),
            new Fragment(3056, new byte[] {
                (byte)0xfa, (byte)0xbe, (byte)0xb7, (byte)0x60,
                (byte)0x28, (byte)0xad, (byte)0xe2, (byte)0xd0, 
                (byte)0xe4, (byte)0x87, (byte)0x22, (byte)0xe4,
                (byte)0x6c, (byte)0x46, (byte)0x15, (byte)0xa3
            }),
            new Fragment(3072, new byte[] {
                (byte)0xc0, (byte)0x5d, (byte)0x88, (byte)0xab,
                (byte)0xd5, (byte)0x03, (byte)0x57, (byte)0xf9, 
                (byte)0x35, (byte)0xa6, (byte)0x3c, (byte)0x59,
                (byte)0xee, (byte)0x53, (byte)0x76, (byte)0x23
            }),
            new Fragment(4080, new byte[] {
                (byte)0xff, (byte)0x38, (byte)0x26, (byte)0x5c,
                (byte)0x16, (byte)0x42, (byte)0xc1, (byte)0xab, 
                (byte)0xe8, (byte)0xd3, (byte)0xc2, (byte)0xfe,
                (byte)0x5e, (byte)0x57, (byte)0x2b, (byte)0xf8
            }),
            new Fragment(4096, new byte[] {
                (byte)0xa3, (byte)0x6a, (byte)0x4c, (byte)0x30,
                (byte)0x1a, (byte)0xe8, (byte)0xac, (byte)0x13, 
                (byte)0x61, (byte)0x0c, (byte)0xcb, (byte)0xc1,
                (byte)0x22, (byte)0x56, (byte)0xca, (byte)0xcc
            }));
            if (CAPI.KeySizes.Contains(keySizes, 16))
            KnownTest(cipher, new byte[] { 
                (byte)0xeb, (byte)0xb4, (byte)0x62, (byte)0x27, 
                (byte)0xc6, (byte)0xcc, (byte)0x8b, (byte)0x37, 
                (byte)0x64, (byte)0x19, (byte)0x10, (byte)0x83, 
                (byte)0x32, (byte)0x22, (byte)0x77, (byte)0x2a
            },
            new Fragment(  0, new byte[] {
                (byte)0x72, (byte)0x0c, (byte)0x94, (byte)0xb6,
                (byte)0x3e, (byte)0xdf, (byte)0x44, (byte)0xe1, 
                (byte)0x31, (byte)0xd9, (byte)0x50, (byte)0xca,
                (byte)0x21, (byte)0x1a, (byte)0x5a, (byte)0x30
            }),
            new Fragment( 16, new byte[] {
                (byte)0xc3, (byte)0x66, (byte)0xfd, (byte)0xea,
                (byte)0xcf, (byte)0x9c, (byte)0xa8, (byte)0x04, 
                (byte)0x36, (byte)0xbe, (byte)0x7c, (byte)0x35,
                (byte)0x84, (byte)0x24, (byte)0xd2, (byte)0x0b
            }),
            new Fragment( 240, new byte[] {
                (byte)0xb3, (byte)0x39, (byte)0x4a, (byte)0x40,
                (byte)0xaa, (byte)0xbf, (byte)0x75, (byte)0xcb, 
                (byte)0xa4, (byte)0x22, (byte)0x82, (byte)0xef,
                (byte)0x25, (byte)0xa0, (byte)0x05, (byte)0x9f
            }),
            new Fragment( 256, new byte[] {
                (byte)0x48, (byte)0x47, (byte)0xd8, (byte)0x1d,
                (byte)0xa4, (byte)0x94, (byte)0x2d, (byte)0xbc, 
                (byte)0x24, (byte)0x9d, (byte)0xef, (byte)0xc4,
                (byte)0x8c, (byte)0x92, (byte)0x2b, (byte)0x9f
            }),
            new Fragment( 496, new byte[] {
                (byte)0x08, (byte)0x12, (byte)0x8c, (byte)0x46,
                (byte)0x9f, (byte)0x27, (byte)0x53, (byte)0x42, 
                (byte)0xad, (byte)0xda, (byte)0x20, (byte)0x2b,
                (byte)0x2b, (byte)0x58, (byte)0xda, (byte)0x95
            }),
            new Fragment( 512, new byte[] {
                (byte)0x97, (byte)0x0d, (byte)0xac, (byte)0xef,
                (byte)0x40, (byte)0xad, (byte)0x98, (byte)0x72, 
                (byte)0x3b, (byte)0xac, (byte)0x5d, (byte)0x69,
                (byte)0x55, (byte)0xb8, (byte)0x17, (byte)0x61
            }),
            new Fragment( 752, new byte[] {
                (byte)0x3c, (byte)0xb8, (byte)0x99, (byte)0x93,
                (byte)0xb0, (byte)0x7b, (byte)0x0c, (byte)0xed, 
                (byte)0x93, (byte)0xde, (byte)0x13, (byte)0xd2,
                (byte)0xa1, (byte)0x10, (byte)0x13, (byte)0xac
            }),
            new Fragment( 768, new byte[] {
                (byte)0xef, (byte)0x2d, (byte)0x67, (byte)0x6f,
                (byte)0x15, (byte)0x45, (byte)0xc2, (byte)0xc1, 
                (byte)0x3d, (byte)0xc6, (byte)0x80, (byte)0xa0,
                (byte)0x2f, (byte)0x4a, (byte)0xdb, (byte)0xfe
            }),
            new Fragment(1008, new byte[] {
                (byte)0xb6, (byte)0x05, (byte)0x95, (byte)0x51,
                (byte)0x4f, (byte)0x24, (byte)0xbc, (byte)0x9f, 
                (byte)0xe5, (byte)0x22, (byte)0xa6, (byte)0xca,
                (byte)0xd7, (byte)0x39, (byte)0x36, (byte)0x44
            }),
            new Fragment(1024, new byte[] {
                (byte)0xb5, (byte)0x15, (byte)0xa8, (byte)0xc5,
                (byte)0x01, (byte)0x17, (byte)0x54, (byte)0xf5, 
                (byte)0x90, (byte)0x03, (byte)0x05, (byte)0x8b,
                (byte)0xdb, (byte)0x81, (byte)0x51, (byte)0x4e
            }),
            new Fragment(1520, new byte[] {
                (byte)0x3c, (byte)0x70, (byte)0x04, (byte)0x7e,
                (byte)0x8c, (byte)0xbc, (byte)0x03, (byte)0x8e, 
                (byte)0x3b, (byte)0x98, (byte)0x20, (byte)0xdb,
                (byte)0x60, (byte)0x1d, (byte)0xa4, (byte)0x95
            }),
            new Fragment(1536, new byte[] {
                (byte)0x11, (byte)0x75, (byte)0xda, (byte)0x6e,
                (byte)0xe7, (byte)0x56, (byte)0xde, (byte)0x46, 
                (byte)0xa5, (byte)0x3e, (byte)0x2b, (byte)0x07,
                (byte)0x56, (byte)0x60, (byte)0xb7, (byte)0x70
            }),
            new Fragment(2032, new byte[] {
                (byte)0x00, (byte)0xa5, (byte)0x42, (byte)0xbb,
                (byte)0xa0, (byte)0x21, (byte)0x11, (byte)0xcc, 
                (byte)0x2c, (byte)0x65, (byte)0xb3, (byte)0x8e,
                (byte)0xbd, (byte)0xba, (byte)0x58, (byte)0x7e
            }),
            new Fragment(2048, new byte[] {
                (byte)0x58, (byte)0x65, (byte)0xfd, (byte)0xbb,
                (byte)0x5b, (byte)0x48, (byte)0x06, (byte)0x41, 
                (byte)0x04, (byte)0xe8, (byte)0x30, (byte)0xb3,
                (byte)0x80, (byte)0xf2, (byte)0xae, (byte)0xde
            }),
            new Fragment(3056, new byte[] {
                (byte)0x34, (byte)0xb2, (byte)0x1a, (byte)0xd2,
                (byte)0xad, (byte)0x44, (byte)0xe9, (byte)0x99, 
                (byte)0xdb, (byte)0x2d, (byte)0x7f, (byte)0x08,
                (byte)0x63, (byte)0xf0, (byte)0xd9, (byte)0xb6
            }),
            new Fragment(3072, new byte[] {
                (byte)0x84, (byte)0xa9, (byte)0x21, (byte)0x8f,
                (byte)0xc3, (byte)0x6e, (byte)0x8a, (byte)0x5f, 
                (byte)0x2c, (byte)0xcf, (byte)0xbe, (byte)0xae,
                (byte)0x53, (byte)0xa2, (byte)0x7d, (byte)0x25
            }),
            new Fragment(4080, new byte[] {
                (byte)0xa2, (byte)0x22, (byte)0x1a, (byte)0x11,
                (byte)0xb8, (byte)0x33, (byte)0xcc, (byte)0xb4, 
                (byte)0x98, (byte)0xa5, (byte)0x95, (byte)0x40,
                (byte)0xf0, (byte)0x54, (byte)0x5f, (byte)0x4a
            }),
            new Fragment(4096, new byte[] {
                (byte)0x5b, (byte)0xbe, (byte)0xb4, (byte)0x78,
                (byte)0x7d, (byte)0x59, (byte)0xe5, (byte)0x37, 
                (byte)0x3f, (byte)0xdb, (byte)0xea, (byte)0x6c,
                (byte)0x6f, (byte)0x75, (byte)0xc2, (byte)0x9b
            }));
            if (CAPI.KeySizes.Contains(keySizes, 24))
            KnownTest(cipher, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18
            },
            new Fragment(  0, new byte[] {
                (byte)0x05, (byte)0x95, (byte)0xe5, (byte)0x7f,
                (byte)0xe5, (byte)0xf0, (byte)0xbb, (byte)0x3c, 
                (byte)0x70, (byte)0x6e, (byte)0xda, (byte)0xc8,
                (byte)0xa4, (byte)0xb2, (byte)0xdb, (byte)0x11
            }),
            new Fragment( 16, new byte[] {
                (byte)0xdf, (byte)0xde, (byte)0x31, (byte)0x34,
                (byte)0x4a, (byte)0x1a, (byte)0xf7, (byte)0x69, 
                (byte)0xc7, (byte)0x4f, (byte)0x07, (byte)0x0a,
                (byte)0xee, (byte)0x9e, (byte)0x23, (byte)0x26
            }),
            new Fragment( 240, new byte[] {
                (byte)0xb0, (byte)0x6b, (byte)0x9b, (byte)0x1e,
                (byte)0x19, (byte)0x5d, (byte)0x13, (byte)0xd8, 
                (byte)0xf4, (byte)0xa7, (byte)0x99, (byte)0x5c,
                (byte)0x45, (byte)0x53, (byte)0xac, (byte)0x05
            }),
            new Fragment( 256, new byte[] {
                (byte)0x6b, (byte)0xd2, (byte)0x37, (byte)0x8e,
                (byte)0xc3, (byte)0x41, (byte)0xc9, (byte)0xa4, 
                (byte)0x2f, (byte)0x37, (byte)0xba, (byte)0x79,
                (byte)0xf8, (byte)0x8a, (byte)0x32, (byte)0xff
            }),
            new Fragment( 496, new byte[] {
                (byte)0xe7, (byte)0x0b, (byte)0xce, (byte)0x1d,
                (byte)0xf7, (byte)0x64, (byte)0x5a, (byte)0xdb, 
                (byte)0x5d, (byte)0x2c, (byte)0x41, (byte)0x30,
                (byte)0x21, (byte)0x5c, (byte)0x35, (byte)0x22
            }),
            new Fragment( 512, new byte[] {
                (byte)0x9a, (byte)0x57, (byte)0x30, (byte)0xc7,
                (byte)0xfc, (byte)0xb4, (byte)0xc9, (byte)0xaf, 
                (byte)0x51, (byte)0xff, (byte)0xda, (byte)0x89,
                (byte)0xc7, (byte)0xf1, (byte)0xad, (byte)0x22
            }),
            new Fragment( 752, new byte[] {
                (byte)0x04, (byte)0x85, (byte)0x05, (byte)0x5f,
                (byte)0xd4, (byte)0xf6, (byte)0xf0, (byte)0xd9, 
                (byte)0x63, (byte)0xef, (byte)0x5a, (byte)0xb9,
                (byte)0xa5, (byte)0x47, (byte)0x69, (byte)0x82
            }),
            new Fragment( 768, new byte[] {
                (byte)0x59, (byte)0x1f, (byte)0xc6, (byte)0x6b,
                (byte)0xcd, (byte)0xa1, (byte)0x0e, (byte)0x45, 
                (byte)0x2b, (byte)0x03, (byte)0xd4, (byte)0x55,
                (byte)0x1f, (byte)0x6b, (byte)0x62, (byte)0xac
            }),
            new Fragment(1008, new byte[] {
                (byte)0x27, (byte)0x53, (byte)0xcc, (byte)0x83,
                (byte)0x98, (byte)0x8a, (byte)0xfa, (byte)0x3e, 
                (byte)0x16, (byte)0x88, (byte)0xa1, (byte)0xd3,
                (byte)0xb4, (byte)0x2c, (byte)0x9a, (byte)0x02
            }),
            new Fragment(1024, new byte[] {
                (byte)0x93, (byte)0x61, (byte)0x0d, (byte)0x52,
                (byte)0x3d, (byte)0x1d, (byte)0x3f, (byte)0x00, 
                (byte)0x62, (byte)0xb3, (byte)0xc2, (byte)0xa3,
                (byte)0xbb, (byte)0xc7, (byte)0xc7, (byte)0xf0
            }),
            new Fragment(1520, new byte[] {
                (byte)0x96, (byte)0xc2, (byte)0x48, (byte)0x61,
                (byte)0x0a, (byte)0xad, (byte)0xed, (byte)0xfe, 
                (byte)0xaf, (byte)0x89, (byte)0x78, (byte)0xc0,
                (byte)0x3d, (byte)0xe8, (byte)0x20, (byte)0x5a
            }),
            new Fragment(1536, new byte[] {
                (byte)0x0e, (byte)0x31, (byte)0x7b, (byte)0x3d,
                (byte)0x1c, (byte)0x73, (byte)0xb9, (byte)0xe9, 
                (byte)0xa4, (byte)0x68, (byte)0x8f, (byte)0x29,
                (byte)0x6d, (byte)0x13, (byte)0x3a, (byte)0x19
            }),
            new Fragment(2032, new byte[] {
                (byte)0xbd, (byte)0xf0, (byte)0xe6, (byte)0xc3,
                (byte)0xcc, (byte)0xa5, (byte)0xb5, (byte)0xb9, 
                (byte)0xd5, (byte)0x33, (byte)0xb6, (byte)0x9c,
                (byte)0x56, (byte)0xad, (byte)0xa1, (byte)0x20
            }),
            new Fragment(2048, new byte[] {
                (byte)0x88, (byte)0xa2, (byte)0x18, (byte)0xb6,
                (byte)0xe2, (byte)0xec, (byte)0xe1, (byte)0xe6, 
                (byte)0x24, (byte)0x6d, (byte)0x44, (byte)0xc7,
                (byte)0x59, (byte)0xd1, (byte)0x9b, (byte)0x10
            }),
            new Fragment(3056, new byte[] {
                (byte)0x68, (byte)0x66, (byte)0x39, (byte)0x7e,
                (byte)0x95, (byte)0xc1, (byte)0x40, (byte)0x53, 
                (byte)0x4f, (byte)0x94, (byte)0x26, (byte)0x34,
                (byte)0x21, (byte)0x00, (byte)0x6e, (byte)0x40
            }),
            new Fragment(3072, new byte[] {
                (byte)0x32, (byte)0xcb, (byte)0x0a, (byte)0x1e,
                (byte)0x95, (byte)0x42, (byte)0xc6, (byte)0xb3, 
                (byte)0xb8, (byte)0xb3, (byte)0x98, (byte)0xab,
                (byte)0xc3, (byte)0xb0, (byte)0xf1, (byte)0xd5
            }),
            new Fragment(4080, new byte[] {
                (byte)0x29, (byte)0xa0, (byte)0xb8, (byte)0xae,
                (byte)0xd5, (byte)0x4a, (byte)0x13, (byte)0x23, 
                (byte)0x24, (byte)0xc6, (byte)0x2e, (byte)0x42,
                (byte)0x3f, (byte)0x54, (byte)0xb4, (byte)0xc8
            }),
            new Fragment(4096, new byte[] {
                (byte)0x3c, (byte)0xb0, (byte)0xf3, (byte)0xb5,
                (byte)0x02, (byte)0x0a, (byte)0x98, (byte)0xb8, 
                (byte)0x2a, (byte)0xf9, (byte)0xfe, (byte)0x15,
                (byte)0x44, (byte)0x84, (byte)0xa1, (byte)0x68
            }));
            if (CAPI.KeySizes.Contains(keySizes, 24))
            KnownTest(cipher, new byte[] { 
                (byte)0xc1, (byte)0x09, (byte)0x16, (byte)0x39, 
                (byte)0x08, (byte)0xeb, (byte)0xe5, (byte)0x1d, 
                (byte)0xeb, (byte)0xb4, (byte)0x62, (byte)0x27, 
                (byte)0xc6, (byte)0xcc, (byte)0x8b, (byte)0x37, 
                (byte)0x64, (byte)0x19, (byte)0x10, (byte)0x83, 
                (byte)0x32, (byte)0x22, (byte)0x77, (byte)0x2a
            },
            new Fragment(  0, new byte[] {
                (byte)0x54, (byte)0xb6, (byte)0x4e, (byte)0x6b,
                (byte)0x5a, (byte)0x20, (byte)0xb5, (byte)0xe2, 
                (byte)0xec, (byte)0x84, (byte)0x59, (byte)0x3d,
                (byte)0xc7, (byte)0x98, (byte)0x9d, (byte)0xa7
            }),
            new Fragment( 16, new byte[] {
                (byte)0xc1, (byte)0x35, (byte)0xee, (byte)0xe2,
                (byte)0x37, (byte)0xa8, (byte)0x54, (byte)0x65, 
                (byte)0xff, (byte)0x97, (byte)0xdc, (byte)0x03,
                (byte)0x92, (byte)0x4f, (byte)0x45, (byte)0xce
            }),
            new Fragment( 240, new byte[] {
                (byte)0xcf, (byte)0xcc, (byte)0x92, (byte)0x2f,
                (byte)0xb4, (byte)0xa1, (byte)0x4a, (byte)0xb4, 
                (byte)0x5d, (byte)0x61, (byte)0x75, (byte)0xaa,
                (byte)0xbb, (byte)0xf2, (byte)0xd2, (byte)0x01
            }),
            new Fragment( 256, new byte[] {
                (byte)0x83, (byte)0x7b, (byte)0x87, (byte)0xe2,
                (byte)0xa4, (byte)0x46, (byte)0xad, (byte)0x0e, 
                (byte)0xf7, (byte)0x98, (byte)0xac, (byte)0xd0,
                (byte)0x2b, (byte)0x94, (byte)0x12, (byte)0x4f
            }),
            new Fragment( 496, new byte[] {
                (byte)0x17, (byte)0xa6, (byte)0xdb, (byte)0xd6,
                (byte)0x64, (byte)0x92, (byte)0x6a, (byte)0x06, 
                (byte)0x36, (byte)0xb3, (byte)0xf4, (byte)0xc3,
                (byte)0x7a, (byte)0x4f, (byte)0x46, (byte)0x94
            }),
            new Fragment( 512, new byte[] {
                (byte)0x4a, (byte)0x5f, (byte)0x9f, (byte)0x26,
                (byte)0xae, (byte)0xee, (byte)0xd4, (byte)0xd4, 
                (byte)0xa2, (byte)0x5f, (byte)0x63, (byte)0x2d,
                (byte)0x30, (byte)0x52, (byte)0x33, (byte)0xd9
            }),
            new Fragment( 752, new byte[] {
                (byte)0x80, (byte)0xa3, (byte)0xd0, (byte)0x1e,
                (byte)0xf0, (byte)0x0c, (byte)0x8e, (byte)0x9a, 
                (byte)0x42, (byte)0x09, (byte)0xc1, (byte)0x7f,
                (byte)0x4e, (byte)0xeb, (byte)0x35, (byte)0x8c
            }),
            new Fragment( 768, new byte[] {
                (byte)0xd1, (byte)0x5e, (byte)0x7d, (byte)0x5f,
                (byte)0xfa, (byte)0xaa, (byte)0xbc, (byte)0x02, 
                (byte)0x07, (byte)0xbf, (byte)0x20, (byte)0x0a,
                (byte)0x11, (byte)0x77, (byte)0x93, (byte)0xa2
            }),
            new Fragment(1008, new byte[] {
                (byte)0x34, (byte)0x96, (byte)0x82, (byte)0xbf,
                (byte)0x58, (byte)0x8e, (byte)0xaa, (byte)0x52, 
                (byte)0xd0, (byte)0xaa, (byte)0x15, (byte)0x60,
                (byte)0x34, (byte)0x6a, (byte)0xea, (byte)0xfa
            }),
            new Fragment(1024, new byte[] {
                (byte)0xf5, (byte)0x85, (byte)0x4c, (byte)0xdb,
                (byte)0x76, (byte)0xc8, (byte)0x89, (byte)0xe3, 
                (byte)0xad, (byte)0x63, (byte)0x35, (byte)0x4e,
                (byte)0x5f, (byte)0x72, (byte)0x75, (byte)0xe3
            }),
            new Fragment(1520, new byte[] {
                (byte)0x53, (byte)0x2c, (byte)0x7c, (byte)0xec,
                (byte)0xcb, (byte)0x39, (byte)0xdf, (byte)0x32, 
                (byte)0x36, (byte)0x31, (byte)0x84, (byte)0x05,
                (byte)0xa4, (byte)0xb1, (byte)0x27, (byte)0x9c
            }),
            new Fragment(1536, new byte[] {
                (byte)0xba, (byte)0xef, (byte)0xe6, (byte)0xd9,
                (byte)0xce, (byte)0xb6, (byte)0x51, (byte)0x84, 
                (byte)0x22, (byte)0x60, (byte)0xe0, (byte)0xd1,
                (byte)0xe0, (byte)0x5e, (byte)0x3b, (byte)0x90
            }),
            new Fragment(2032, new byte[] {
                (byte)0xe8, (byte)0x2d, (byte)0x8c, (byte)0x6d,
                (byte)0xb5, (byte)0x4e, (byte)0x3c, (byte)0x63, 
                (byte)0x3f, (byte)0x58, (byte)0x1c, (byte)0x95,
                (byte)0x2b, (byte)0xa0, (byte)0x42, (byte)0x07
            }),
            new Fragment(2048, new byte[] {
                (byte)0x4b, (byte)0x16, (byte)0xe5, (byte)0x0a,
                (byte)0xbd, (byte)0x38, (byte)0x1b, (byte)0xd7, 
                (byte)0x09, (byte)0x00, (byte)0xa9, (byte)0xcd,
                (byte)0x9a, (byte)0x62, (byte)0xcb, (byte)0x23
            }),
            new Fragment(3056, new byte[] {
                (byte)0x36, (byte)0x82, (byte)0xee, (byte)0x33,
                (byte)0xbd, (byte)0x14, (byte)0x8b, (byte)0xd9, 
                (byte)0xf5, (byte)0x86, (byte)0x56, (byte)0xcd,
                (byte)0x8f, (byte)0x30, (byte)0xd9, (byte)0xfb
            }),
            new Fragment(3072, new byte[] {
                (byte)0x1e, (byte)0x5a, (byte)0x0b, (byte)0x84,
                (byte)0x75, (byte)0x04, (byte)0x5d, (byte)0x9b, 
                (byte)0x20, (byte)0xb2, (byte)0x62, (byte)0x86,
                (byte)0x24, (byte)0xed, (byte)0xfd, (byte)0x9e
            }),
            new Fragment(4080, new byte[] {
                (byte)0x63, (byte)0xed, (byte)0xd6, (byte)0x84,
                (byte)0xfb, (byte)0x82, (byte)0x62, (byte)0x82, 
                (byte)0xfe, (byte)0x52, (byte)0x8f, (byte)0x9c,
                (byte)0x0e, (byte)0x92, (byte)0x37, (byte)0xbc
            }),
            new Fragment(4096, new byte[] {
                (byte)0xe4, (byte)0xdd, (byte)0x2e, (byte)0x98,
                (byte)0xd6, (byte)0x96, (byte)0x0f, (byte)0xae, 
                (byte)0x0b, (byte)0x43, (byte)0x54, (byte)0x54,
                (byte)0x56, (byte)0x74, (byte)0x33, (byte)0x91
            }));
            if (CAPI.KeySizes.Contains(keySizes, 32))
            KnownTest(cipher, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
                (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, 
                (byte)0x1d, (byte)0x1e, (byte)0x1f, (byte)0x20
            },
            new Fragment(  0, new byte[] {
                (byte)0xea, (byte)0xa6, (byte)0xbd, (byte)0x25,
                (byte)0x88, (byte)0x0b, (byte)0xf9, (byte)0x3d, 
                (byte)0x3f, (byte)0x5d, (byte)0x1e, (byte)0x4c,
                (byte)0xa2, (byte)0x61, (byte)0x1d, (byte)0x91
            }),
            new Fragment( 16, new byte[] {
                (byte)0xcf, (byte)0xa4, (byte)0x5c, (byte)0x9f,
                (byte)0x7e, (byte)0x71, (byte)0x4b, (byte)0x54, 
                (byte)0xbd, (byte)0xfa, (byte)0x80, (byte)0x02,
                (byte)0x7c, (byte)0xb1, (byte)0x43, (byte)0x80
            }),
            new Fragment( 240, new byte[] {
                (byte)0x11, (byte)0x4a, (byte)0xe3, (byte)0x44,
                (byte)0xde, (byte)0xd7, (byte)0x1b, (byte)0x35, 
                (byte)0xf2, (byte)0xe6, (byte)0x0f, (byte)0xeb,
                (byte)0xad, (byte)0x72, (byte)0x7f, (byte)0xd8
            }),
            new Fragment( 256, new byte[] {
                (byte)0x02, (byte)0xe1, (byte)0xe7, (byte)0x05,
                (byte)0x6b, (byte)0x0f, (byte)0x62, (byte)0x39, 
                (byte)0x00, (byte)0x49, (byte)0x64, (byte)0x22,
                (byte)0x94, (byte)0x3e, (byte)0x97, (byte)0xb6
            }),
            new Fragment( 496, new byte[] {
                (byte)0x91, (byte)0xcb, (byte)0x93, (byte)0xc7,
                (byte)0x87, (byte)0x96, (byte)0x4e, (byte)0x10, 
                (byte)0xd9, (byte)0x52, (byte)0x7d, (byte)0x99,
                (byte)0x9c, (byte)0x6f, (byte)0x93, (byte)0x6b
            }),
            new Fragment( 512, new byte[] {
                (byte)0x49, (byte)0xb1, (byte)0x8b, (byte)0x42,
                (byte)0xf8, (byte)0xe8, (byte)0x36, (byte)0x7c, 
                (byte)0xbe, (byte)0xb5, (byte)0xef, (byte)0x10,
                (byte)0x4b, (byte)0xa1, (byte)0xc7, (byte)0xcd
            }),
            new Fragment( 752, new byte[] {
                (byte)0x87, (byte)0x08, (byte)0x4b, (byte)0x3b,
                (byte)0xa7, (byte)0x00, (byte)0xba, (byte)0xde, 
                (byte)0x95, (byte)0x56, (byte)0x10, (byte)0x67,
                (byte)0x27, (byte)0x45, (byte)0xb3, (byte)0x74
            }),
            new Fragment( 768, new byte[] {
                (byte)0xe7, (byte)0xa7, (byte)0xb9, (byte)0xe9,
                (byte)0xec, (byte)0x54, (byte)0x0d, (byte)0x5f, 
                (byte)0xf4, (byte)0x3b, (byte)0xdb, (byte)0x12,
                (byte)0x79, (byte)0x2d, (byte)0x1b, (byte)0x35
            }),
            new Fragment(1008, new byte[] {
                (byte)0xc7, (byte)0x99, (byte)0xb5, (byte)0x96,
                (byte)0x73, (byte)0x8f, (byte)0x6b, (byte)0x01, 
                (byte)0x8c, (byte)0x76, (byte)0xc7, (byte)0x4b,
                (byte)0x17, (byte)0x59, (byte)0xbd, (byte)0x90
            }),
            new Fragment(1024, new byte[] {
                (byte)0x7f, (byte)0xec, (byte)0x5b, (byte)0xfd,
                (byte)0x9f, (byte)0x9b, (byte)0x89, (byte)0xce, 
                (byte)0x65, (byte)0x48, (byte)0x30, (byte)0x90,
                (byte)0x92, (byte)0xd7, (byte)0xe9, (byte)0x58
            }),
            new Fragment(1520, new byte[] {
                (byte)0x40, (byte)0xf2, (byte)0x50, (byte)0xb2,
                (byte)0x6d, (byte)0x1f, (byte)0x09, (byte)0x6a, 
                (byte)0x4a, (byte)0xfd, (byte)0x4c, (byte)0x34,
                (byte)0x0a, (byte)0x58, (byte)0x88, (byte)0x15
            }),
            new Fragment(1536, new byte[] {
                (byte)0x3e, (byte)0x34, (byte)0x13, (byte)0x5c,
                (byte)0x79, (byte)0xdb, (byte)0x01, (byte)0x02, 
                (byte)0x00, (byte)0x76, (byte)0x76, (byte)0x51,
                (byte)0xcf, (byte)0x26, (byte)0x30, (byte)0x73
            }),
            new Fragment(2032, new byte[] {
                (byte)0xf6, (byte)0x56, (byte)0xab, (byte)0xcc,
                (byte)0xf8, (byte)0x8d, (byte)0xd8, (byte)0x27, 
                (byte)0x02, (byte)0x7b, (byte)0x2c, (byte)0xe9,
                (byte)0x17, (byte)0xd4, (byte)0x64, (byte)0xec
            }),
            new Fragment(2048, new byte[] {
                (byte)0x18, (byte)0xb6, (byte)0x25, (byte)0x03,
                (byte)0xbf, (byte)0xbc, (byte)0x07, (byte)0x7f, 
                (byte)0xba, (byte)0xbb, (byte)0x98, (byte)0xf2,
                (byte)0x0d, (byte)0x98, (byte)0xab, (byte)0x34
            }),
            new Fragment(3056, new byte[] {
                (byte)0x8a, (byte)0xed, (byte)0x95, (byte)0xee,
                (byte)0x5b, (byte)0x0d, (byte)0xcb, (byte)0xfb, 
                (byte)0xef, (byte)0x4e, (byte)0xb2, (byte)0x1d,
                (byte)0x3a, (byte)0x3f, (byte)0x52, (byte)0xf9
            }),
            new Fragment(3072, new byte[] {
                (byte)0x62, (byte)0x5a, (byte)0x1a, (byte)0xb0,
                (byte)0x0e, (byte)0xe3, (byte)0x9a, (byte)0x53, 
                (byte)0x27, (byte)0x34, (byte)0x6b, (byte)0xdd,
                (byte)0xb0, (byte)0x1a, (byte)0x9c, (byte)0x18
            }),
            new Fragment(4080, new byte[] {
                (byte)0xa1, (byte)0x3a, (byte)0x7c, (byte)0x79,
                (byte)0xc7, (byte)0xe1, (byte)0x19, (byte)0xb5, 
                (byte)0xab, (byte)0x02, (byte)0x96, (byte)0xab,
                (byte)0x28, (byte)0xc3, (byte)0x00, (byte)0xb9
            }),
            new Fragment(4096, new byte[] {
                (byte)0xf3, (byte)0xe4, (byte)0xc0, (byte)0xa2,
                (byte)0xe0, (byte)0x2d, (byte)0x1d, (byte)0x01, 
                (byte)0xf7, (byte)0xf0, (byte)0xa7, (byte)0x46,
                (byte)0x18, (byte)0xaf, (byte)0x2b, (byte)0x48
            }));
            if (CAPI.KeySizes.Contains(keySizes, 32))
            KnownTest(cipher, new byte[] { 
                (byte)0x1a, (byte)0xda, (byte)0x31, (byte)0xd5, 
                (byte)0xcf, (byte)0x68, (byte)0x82, (byte)0x21, 
                (byte)0xc1, (byte)0x09, (byte)0x16, (byte)0x39, 
                (byte)0x08, (byte)0xeb, (byte)0xe5, (byte)0x1d, 
                (byte)0xeb, (byte)0xb4, (byte)0x62, (byte)0x27, 
                (byte)0xc6, (byte)0xcc, (byte)0x8b, (byte)0x37, 
                (byte)0x64, (byte)0x19, (byte)0x10, (byte)0x83, 
                (byte)0x32, (byte)0x22, (byte)0x77, (byte)0x2a
            },
            new Fragment(  0, new byte[] {
                (byte)0xdd, (byte)0x5b, (byte)0xcb, (byte)0x00,
                (byte)0x18, (byte)0xe9, (byte)0x22, (byte)0xd4, 
                (byte)0x94, (byte)0x75, (byte)0x9d, (byte)0x7c,
                (byte)0x39, (byte)0x5d, (byte)0x02, (byte)0xd3
            }),
            new Fragment( 16, new byte[] {
                (byte)0xc8, (byte)0x44, (byte)0x6f, (byte)0x8f,
                (byte)0x77, (byte)0xab, (byte)0xf7, (byte)0x37, 
                (byte)0x68, (byte)0x53, (byte)0x53, (byte)0xeb,
                (byte)0x89, (byte)0xa1, (byte)0xc9, (byte)0xeb
            }),
            new Fragment( 240, new byte[] {
                (byte)0xaf, (byte)0x3e, (byte)0x30, (byte)0xf9,
                (byte)0xc0, (byte)0x95, (byte)0x04, (byte)0x59, 
                (byte)0x38, (byte)0x15, (byte)0x15, (byte)0x75,
                (byte)0xc3, (byte)0xfb, (byte)0x90, (byte)0x98
            }),
            new Fragment( 256, new byte[] {
                (byte)0xf8, (byte)0xcb, (byte)0x62, (byte)0x74,
                (byte)0xdb, (byte)0x99, (byte)0xb8, (byte)0x0b, 
                (byte)0x1d, (byte)0x20, (byte)0x12, (byte)0xa9,
                (byte)0x8e, (byte)0xd4, (byte)0x8f, (byte)0x0e
            }),
            new Fragment( 496, new byte[] {
                (byte)0x25, (byte)0xc3, (byte)0x00, (byte)0x5a,
                (byte)0x1c, (byte)0xb8, (byte)0x5d, (byte)0xe0, 
                (byte)0x76, (byte)0x25, (byte)0x98, (byte)0x39,
                (byte)0xab, (byte)0x71, (byte)0x98, (byte)0xab
            }),
            new Fragment( 512, new byte[] {
                (byte)0x9d, (byte)0xcb, (byte)0xc1, (byte)0x83,
                (byte)0xe8, (byte)0xcb, (byte)0x99, (byte)0x4b, 
                (byte)0x72, (byte)0x7b, (byte)0x75, (byte)0xbe,
                (byte)0x31, (byte)0x80, (byte)0x76, (byte)0x9c
            }),
            new Fragment( 752, new byte[] {
                (byte)0xa1, (byte)0xd3, (byte)0x07, (byte)0x8d,
                (byte)0xfa, (byte)0x91, (byte)0x69, (byte)0x50, 
                (byte)0x3e, (byte)0xd9, (byte)0xd4, (byte)0x49,
                (byte)0x1d, (byte)0xee, (byte)0x4e, (byte)0xb2
            }),
            new Fragment( 768, new byte[] {
                (byte)0x85, (byte)0x14, (byte)0xa5, (byte)0x49,
                (byte)0x58, (byte)0x58, (byte)0x09, (byte)0x6f, 
                (byte)0x59, (byte)0x6e, (byte)0x4b, (byte)0xcd,
                (byte)0x66, (byte)0xb1, (byte)0x06, (byte)0x65
            }),
            new Fragment(1008, new byte[] {
                (byte)0x5f, (byte)0x40, (byte)0xd5, (byte)0x9e,
                (byte)0xc1, (byte)0xb0, (byte)0x3b, (byte)0x33, 
                (byte)0x73, (byte)0x8e, (byte)0xfa, (byte)0x60,
                (byte)0xb2, (byte)0x25, (byte)0x5d, (byte)0x31
            }),
            new Fragment(1024, new byte[] {
                (byte)0x34, (byte)0x77, (byte)0xc7, (byte)0xf7,
                (byte)0x64, (byte)0xa4, (byte)0x1b, (byte)0xac, 
                (byte)0xef, (byte)0xf9, (byte)0x0b, (byte)0xf1,
                (byte)0x4f, (byte)0x92, (byte)0xb7, (byte)0xcc
            }),
            new Fragment(1520, new byte[] {
                (byte)0xac, (byte)0x4e, (byte)0x95, (byte)0x36,
                (byte)0x8d, (byte)0x99, (byte)0xb9, (byte)0xeb, 
                (byte)0x78, (byte)0xb8, (byte)0xda, (byte)0x8f,
                (byte)0x81, (byte)0xff, (byte)0xa7, (byte)0x95
            }),
            new Fragment(1536, new byte[] {
                (byte)0x8c, (byte)0x3c, (byte)0x13, (byte)0xf8,
                (byte)0xc2, (byte)0x38, (byte)0x8b, (byte)0xb7, 
                (byte)0x3f, (byte)0x38, (byte)0x57, (byte)0x6e,
                (byte)0x65, (byte)0xb7, (byte)0xc4, (byte)0x46
            }),
            new Fragment(2032, new byte[] {
                (byte)0x13, (byte)0xc4, (byte)0xb9, (byte)0xc1,
                (byte)0xdf, (byte)0xb6, (byte)0x65, (byte)0x79, 
                (byte)0xed, (byte)0xdd, (byte)0x8a, (byte)0x28,
                (byte)0x0b, (byte)0x9f, (byte)0x73, (byte)0x16
            }),
            new Fragment(2048, new byte[] {
                (byte)0xdd, (byte)0xd2, (byte)0x78, (byte)0x20,
                (byte)0x55, (byte)0x01, (byte)0x26, (byte)0x69, 
                (byte)0x8e, (byte)0xfa, (byte)0xad, (byte)0xc6,
                (byte)0x4b, (byte)0x64, (byte)0xf6, (byte)0x6e
            }),
            new Fragment(3056, new byte[] {
                (byte)0xf0, (byte)0x8f, (byte)0x2e, (byte)0x66,
                (byte)0xd2, (byte)0x8e, (byte)0xd1, (byte)0x43, 
                (byte)0xf3, (byte)0xa2, (byte)0x37, (byte)0xcf,
                (byte)0x9d, (byte)0xe7, (byte)0x35, (byte)0x59
            }),
            new Fragment(3072, new byte[] {
                (byte)0x9e, (byte)0xa3, (byte)0x6c, (byte)0x52,
                (byte)0x55, (byte)0x31, (byte)0xb8, (byte)0x80, 
                (byte)0xba, (byte)0x12, (byte)0x43, (byte)0x34,
                (byte)0xf5, (byte)0x7b, (byte)0x0b, (byte)0x70
            }),
            new Fragment(4080, new byte[] {
                (byte)0xd5, (byte)0xa3, (byte)0x9e, (byte)0x3d,
                (byte)0xfc, (byte)0xc5, (byte)0x02, (byte)0x80, 
                (byte)0xba, (byte)0xc4, (byte)0xa6, (byte)0xb5,
                (byte)0xaa, (byte)0x0d, (byte)0xca, (byte)0x7d
            }),
            new Fragment(4096, new byte[] {
                (byte)0x37, (byte)0x0b, (byte)0x1c, (byte)0x1f,
                (byte)0xe6, (byte)0x55, (byte)0x91, (byte)0x6d, 
                (byte)0x97, (byte)0xfd, (byte)0x0d, (byte)0x47,
                (byte)0xca, (byte)0x1d, (byte)0x72, (byte)0xb8
            }));
        }
    }
}
