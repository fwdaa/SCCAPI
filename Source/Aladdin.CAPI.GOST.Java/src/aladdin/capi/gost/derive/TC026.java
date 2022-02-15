package aladdin.capi.gost.derive;
import aladdin.capi.derive.*;
import aladdin.capi.*; 
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм диверсификации ключа
///////////////////////////////////////////////////////////////////////////
public class TC026 extends TREEKDF
{
    // значение по умолчанию
    private static final byte[] DEFAULT_LABEL = new byte[] {
        (byte)0x26, (byte)0xBD, (byte)0xB8, (byte)0x78         
    }; 
	// конструктор
	public TC026(Mac hmac_gostr3411_2012_256) 
    { 
        // сохранить переданные параметры
        this(hmac_gostr3411_2012_256, DEFAULT_LABEL); 
    } 
	// конструктор
	public TC026(Mac hmac_gostr3411_2012_256, byte[] label) 
    { 
        // сохранить переданные параметры
        super(hmac_gostr3411_2012_256, label, 1); 
    } 
	// сгенерировать ключ
	@Override public ISecretKey deriveKey(ISecretKey key, 
        byte[] seed, SecretKeyFactory keyFactory, int deriveSize) 
            throws IOException, InvalidKeyException
    {
        // указать размер генерируемого ключа
        if (deriveSize < 0) deriveSize = 32; 
        
        // вызвать базовую функцию
        return super.deriveKey(key, seed, keyFactory, deriveSize); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Mac hmac_gostr3411_2012_256) throws Exception
    {
        // создать алгоритм наследования ключа
        try (KeyDerive kdfAlgorithm = new TC026(hmac_gostr3411_2012_256)) 
        {
            // выполнить тест
            knownTest(kdfAlgorithm, new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, 
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, 
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
                (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
                (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, 
                (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f
            }, new byte[] {
                (byte)0xaf, (byte)0x21, (byte)0x43, (byte)0x41, 
                (byte)0x45, (byte)0x65, (byte)0x63, (byte)0x78
            }, new byte[] {
                (byte)0xa1, (byte)0xaa, (byte)0x5f, (byte)0x7d, 
                (byte)0xe4, (byte)0x02, (byte)0xd7, (byte)0xb3, 
                (byte)0xd3, (byte)0x23, (byte)0xf2, (byte)0x99, 
                (byte)0x1c, (byte)0x8d, (byte)0x45, (byte)0x34, 
                (byte)0x01, (byte)0x31, (byte)0x37, (byte)0x01, 
                (byte)0x0a, (byte)0x83, (byte)0x75, (byte)0x4f, 
                (byte)0xd0, (byte)0xaf, (byte)0x6d, (byte)0x7c, 
                (byte)0xd4, (byte)0x92, (byte)0x2e, (byte)0xd9
            });
            // выполнить тест
            knownTest(kdfAlgorithm, new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, 
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, 
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
                (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
                (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, 
                (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f
            }, new byte[] {
                (byte)0xaf, (byte)0x21, (byte)0x43, (byte)0x41, 
                (byte)0x45, (byte)0x65, (byte)0x63, (byte)0x78
            }, new byte[] {
                (byte)0x22, (byte)0xb6, (byte)0x83, (byte)0x78, 
                (byte)0x45, (byte)0xc6, (byte)0xbe, (byte)0xf6, 
                (byte)0x5e, (byte)0xa7, (byte)0x16, (byte)0x72, 
                (byte)0xb2, (byte)0x65, (byte)0x83, (byte)0x10, 
                (byte)0x86, (byte)0xd3, (byte)0xc7, (byte)0x6a, 
                (byte)0xeb, (byte)0xe6, (byte)0xda, (byte)0xe9, 
                (byte)0x1c, (byte)0xad, (byte)0x51, (byte)0xd8, 
                (byte)0x3f, (byte)0x79, (byte)0xd1, (byte)0x6b,
                (byte)0x07, (byte)0x4c, (byte)0x93, (byte)0x30, 
                (byte)0x59, (byte)0x9d, (byte)0x7f, (byte)0x8d, 
                (byte)0x71, (byte)0x2f, (byte)0xca, (byte)0x54, 
                (byte)0x39, (byte)0x2f, (byte)0x4d, (byte)0xdd,
                (byte)0xe9, (byte)0x37, (byte)0x51, (byte)0x20, 
                (byte)0x6b, (byte)0x35, (byte)0x84, (byte)0xc8, 
                (byte)0xf4, (byte)0x3f, (byte)0x9e, (byte)0x6d, 
                (byte)0xc5, (byte)0x15, (byte)0x31, (byte)0xf9        
            });
        }
    }    
}
