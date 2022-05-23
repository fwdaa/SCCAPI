package aladdin.capi.gost.engine;
import aladdin.capi.*;
import aladdin.capi.gost.derive.*;
import aladdin.capi.gost.mac.*;
import aladdin.capi.gost.mode.gostr3412.*;
import aladdin.math.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ГОСТ P34.12-2015 (размер блока 8 байт)
///////////////////////////////////////////////////////////////////////////
public class GOSTR3412_M extends GOST28147
{
    // способ кодирования чисел
    public static final Endian ENDIAN = Endian.BIG_ENDIAN;
    
    // конструктор
    public GOSTR3412_M(byte[] sbox) { super(sbox, ENDIAN); }
    
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа (блок 64-бит)
    ////////////////////////////////////////////////////////////////////////////
    public static void test(IBlockCipher blockCipher) throws Exception
    {
        byte[] key = new byte[] {
            (byte)0xff, (byte)0xee, (byte)0xdd, (byte)0xcc, 
            (byte)0xbb, (byte)0xaa, (byte)0x99, (byte)0x88,
            (byte)0x77, (byte)0x66, (byte)0x55, (byte)0x44, 
            (byte)0x33, (byte)0x22, (byte)0x11, (byte)0x00,
            (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3, 
            (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7,
            (byte)0xf8, (byte)0xf9, (byte)0xfa, (byte)0xfb, 
            (byte)0xfc, (byte)0xfd, (byte)0xfe, (byte)0xff
        };
        byte[] data = new byte[] {
            (byte)0x92, (byte)0xde, (byte)0xf0, (byte)0x6b, 
            (byte)0x3c, (byte)0x13, (byte)0x0a, (byte)0x59,
            (byte)0xdb, (byte)0x54, (byte)0xc7, (byte)0x04, 
            (byte)0xf8, (byte)0x18, (byte)0x9d, (byte)0x20,
            (byte)0x4a, (byte)0x98, (byte)0xfb, (byte)0x2e, 
            (byte)0x67, (byte)0xa8, (byte)0x02, (byte)0x4c,
            (byte)0x89, (byte)0x12, (byte)0x40, (byte)0x9b, 
            (byte)0x17, (byte)0xb5, (byte)0x7e, (byte)0x41
        }; 
        CipherMode modeECB = new CipherMode.ECB(); 
        
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(modeECB))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, new byte[] {
                (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 
                (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10
            }, new byte[] {
                (byte)0x4e, (byte)0xe9, (byte)0x01, (byte)0xe5, 
                (byte)0xc2, (byte)0xd8, (byte)0xca, (byte)0x3d
            });
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x2b, (byte)0x07, (byte)0x3f, (byte)0x04, 
                (byte)0x94, (byte)0xf3, (byte)0x72, (byte)0xa0,            
                (byte)0xde, (byte)0x70, (byte)0xe7, (byte)0x15, 
                (byte)0xd3, (byte)0x55, (byte)0x6e, (byte)0x48,
                (byte)0x11, (byte)0xd8, (byte)0xd9, (byte)0xe9, 
                (byte)0xea, (byte)0xcf, (byte)0xbc, (byte)0x1e,
                (byte)0x7c, (byte)0x68, (byte)0x26, (byte)0x09, 
                (byte)0x96, (byte)0xc6, (byte)0x7e, (byte)0xfb
            });
        }
        CipherMode mode = new CipherMode.CTR(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78
        }, 8); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x4e, (byte)0x98, (byte)0x11, (byte)0x0c, 
                (byte)0x97, (byte)0xb7, (byte)0xb9, (byte)0x3c, 
                (byte)0x3e, (byte)0x25, (byte)0x0d, (byte)0x93, 
                (byte)0xd6, (byte)0xe8, (byte)0x5d, (byte)0x69, 
                (byte)0x13, (byte)0x6d, (byte)0x86, (byte)0x88, 
                (byte)0x07, (byte)0xb2, (byte)0xdb, (byte)0xef, 
                (byte)0x56, (byte)0x8e, (byte)0xb6, (byte)0x80, 
                (byte)0xab, (byte)0x52, (byte)0xa1, (byte)0x2d
            });
        }
        mode = new CipherMode.OFB(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef, 
            (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, 
            (byte)0x0a, (byte)0xbc, (byte)0xde, (byte)0xf1
        }, 8); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0xdb, (byte)0x37, (byte)0xe0, (byte)0xe2, 
                (byte)0x66, (byte)0x90, (byte)0x3c, (byte)0x83,  
                (byte)0x0d, (byte)0x46, (byte)0x64, (byte)0x4c, 
                (byte)0x1f, (byte)0x9a, (byte)0x08, (byte)0x9c, 
                (byte)0xa0, (byte)0xf8, (byte)0x30, (byte)0x62, 
                (byte)0x43, (byte)0x0e, (byte)0x32, (byte)0x7e,
                (byte)0xc8, (byte)0x24, (byte)0xef, (byte)0xb8, 
                (byte)0xbd, (byte)0x4f, (byte)0xdb, (byte)0x05
            });
        }
        mode = new CipherMode.CBC(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef, 
            (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, 
            (byte)0x0a, (byte)0xbc, (byte)0xde, (byte)0xf1, 
            (byte)0x34, (byte)0x56, (byte)0x78, (byte)0x90, 
            (byte)0xab, (byte)0xcd, (byte)0xef, (byte)0x12
        }, 8); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0x96, (byte)0xd1, (byte)0xb0, (byte)0x5e, 
                (byte)0xea, (byte)0x68, (byte)0x39, (byte)0x19, 
                (byte)0xaf, (byte)0xf7, (byte)0x61, (byte)0x29, 
                (byte)0xab, (byte)0xb9, (byte)0x37, (byte)0xb9, 
                (byte)0x50, (byte)0x58, (byte)0xb4, (byte)0xa1, 
                (byte)0xc4, (byte)0xbc, (byte)0x00, (byte)0x19, 
                (byte)0x20, (byte)0xb7, (byte)0x8b, (byte)0x1a, 
                (byte)0x7c, (byte)0xd7, (byte)0xe6, (byte)0x67
            });
        }
        mode = new CipherMode.CFB(new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, 
            (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef, 
            (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, 
            (byte)0x0a, (byte)0xbc, (byte)0xde, (byte)0xf1
        }, 8); 
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        { 
            // выполнить тест
            Cipher.knownTest(cipher, PaddingMode.NONE, key, data, new byte[] {
                (byte)0xdb, (byte)0x37, (byte)0xe0, (byte)0xe2, 
                (byte)0x66, (byte)0x90, (byte)0x3c, (byte)0x83, 
                (byte)0x0d, (byte)0x46, (byte)0x64, (byte)0x4c, 
                (byte)0x1f, (byte)0x9a, (byte)0x08, (byte)0x9c, 
                (byte)0x24, (byte)0xbd, (byte)0xd2, (byte)0x03, 
                (byte)0x53, (byte)0x15, (byte)0xd3, (byte)0x8b, 
                (byte)0xbc, (byte)0xc0, (byte)0x32, (byte)0x14, 
                (byte)0x21, (byte)0x07, (byte)0x55, (byte)0x05
            });
        }
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(modeECB))
        {
            // создать алгоритм смены ключа для OMAC-ACPKM
            try (KeyDerive keyMeshing = new ACPKM(cipher))
            {
                // указать параметры режима
                CipherMode.CTR ctrParameters = new CipherMode.CTR(
                    new byte[] { 
                       (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78 
                    }, 
                    cipher.blockSize()
                ); 
                // создать режим CBC со специальной сменой ключа
                try (Cipher cipherCTR = new CTR(cipher, ctrParameters, keyMeshing, 16))
                {
                    key = new byte[] {
                        (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                        (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF,
                        (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                        (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                        (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, 
                        (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
                        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                        (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF,
                    }; 
                    data = new byte[] {
                        (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                        (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
                        (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, 
                        (byte)0xBB, (byte)0xAA, (byte)0x99, (byte)0x88,
                        (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                        (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                        (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                        (byte)0xCC, (byte)0xEE, (byte)0xFF, (byte)0x0A,
                        (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                        (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, 
                        (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, 
                        (byte)0xEE, (byte)0xFF, (byte)0x0A, (byte)0x00, 
                        (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, 
                        (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99, 
                    }; 
                    // выполнить тест
                    Cipher.knownTest(cipherCTR, PaddingMode.NONE, key, data, new byte[] {
                        (byte)0x2A, (byte)0xB8, (byte)0x1D, (byte)0xEE, 
                        (byte)0xEB, (byte)0x1E, (byte)0x4C, (byte)0xAB,
                        (byte)0x68, (byte)0xE1, (byte)0x04, (byte)0xC4, 
                        (byte)0xBD, (byte)0x6B, (byte)0x94, (byte)0xEA,
                        (byte)0xC7, (byte)0x2C, (byte)0x67, (byte)0xAF, 
                        (byte)0x6C, (byte)0x2E, (byte)0x5B, (byte)0x6B,
                        (byte)0x0E, (byte)0xAF, (byte)0xB6, (byte)0x17, 
                        (byte)0x70, (byte)0xF1, (byte)0xB3, (byte)0x2E,
                        (byte)0xA1, (byte)0xAE, (byte)0x71, (byte)0x14, 
                        (byte)0x9E, (byte)0xED, (byte)0x13, (byte)0x82, 
                        (byte)0xAB, (byte)0xD4, (byte)0x67, (byte)0x18, 
                        (byte)0x06, (byte)0x72, (byte)0xEC, (byte)0x6F, 
                        (byte)0x84, (byte)0xA2, (byte)0xF1, (byte)0x5B, 
                        (byte)0x3F, (byte)0xCA, (byte)0x72, (byte)0xC1, 
                    });
                }
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // GOSTR3412-MAC 
    ////////////////////////////////////////////////////////////////////////////
    public static void testMAC(IBlockCipher blockCipher) throws Exception
    {
        // указать начальную синхропосылку
        byte[] start = new byte[blockCipher.blockSize()]; 
        
        // создать алгоритм выработки имитовставки
        try (Mac macAlgorithm = aladdin.capi.mac.OMAC1.create(blockCipher, start))
        {
            Mac.knownTest(macAlgorithm, new byte[] {
                (byte)0xff, (byte)0xee, (byte)0xdd, (byte)0xcc, 
                (byte)0xbb, (byte)0xaa, (byte)0x99, (byte)0x88,
                (byte)0x77, (byte)0x66, (byte)0x55, (byte)0x44, 
                (byte)0x33, (byte)0x22, (byte)0x11, (byte)0x00,
                (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3, 
                (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7,
                (byte)0xf8, (byte)0xf9, (byte)0xfa, (byte)0xfb, 
                (byte)0xfc, (byte)0xfd, (byte)0xfe, (byte)0xff
            }, 1, new byte[] {
                (byte)0x92, (byte)0xde, (byte)0xf0, (byte)0x6b, 
                (byte)0x3c, (byte)0x13, (byte)0x0a, (byte)0x59,
                (byte)0xdb, (byte)0x54, (byte)0xc7, (byte)0x04, 
                (byte)0xf8, (byte)0x18, (byte)0x9d, (byte)0x20,
                (byte)0x4a, (byte)0x98, (byte)0xfb, (byte)0x2e, 
                (byte)0x67, (byte)0xa8, (byte)0x02, (byte)0x4c,
                (byte)0x89, (byte)0x12, (byte)0x40, (byte)0x9b, 
                (byte)0x17, (byte)0xb5, (byte)0x7e, (byte)0x41
            }, new byte[] {
                (byte)0x15, (byte)0x4e, (byte)0x72, (byte)0x10            
            });
        }
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.ECB()))
        {
            // создать алгоритм выработки имитовставки
            try (Mac macAlgorithm = GOSTR3412ACPKM.create(cipher, 16, 80, 8))
            {
                byte[] key = new byte[] {
                    (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                    (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF,
                    (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                    (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                    (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, 
                    (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
                    (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                    (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF,
                }; 
                Mac.knownTest(macAlgorithm, key, 1, new byte[] {
                    (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                    (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
                    (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, 
                }, new byte[] {
                    (byte)0xA0, (byte)0x54, (byte)0x0E, (byte)0x37,             
                    (byte)0x30, (byte)0xAC, (byte)0xBC, (byte)0xF3,             
                });
                Mac.knownTest(macAlgorithm, key, 1, new byte[] {
                    (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                    (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
                    (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, 
                    (byte)0xBB, (byte)0xAA, (byte)0x99, (byte)0x88, 
                    (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                    (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
                    (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                    (byte)0xCC, (byte)0xEE, (byte)0xFF, (byte)0x0A, 
                    (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                    (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, 
                }, new byte[] {
                    (byte)0x34, (byte)0x00, (byte)0x8D, (byte)0xAD,             
                    (byte)0x54, (byte)0x96, (byte)0xBB, (byte)0x8E,             
                });
            }
        }
    }
}
