package aladdin.capi.gost.sign.gostr3410;
import aladdin.capi.gost.gostr3410.*; 
import aladdin.math.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*;
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////
public class DHSignHash extends SignHash
{
    @Override public byte[] sign(aladdin.capi.IPrivateKey privateKey, 
        IRand rand, AlgorithmIdentifier hashParameters, byte[] hash) throws IOException
    {
        // преобразовать тип ключа
        IDHPrivateKey privateKeyS = (IDHPrivateKey)privateKey;

        // получить параметры алгоритма
        IDHParameters parameters = (IDHParameters)privateKeyS.parameters(); 

        // создать экспоненту
        BigInteger h = Convert.toBigInteger(hash, Endian.LITTLE_ENDIAN);
            
        // проверить значение 
        if (h.signum() == 0) h = BigInteger.ONE; 

        // извлечь параметры алгоритма
        BigInteger p = parameters.getP(); BigInteger q = parameters.getQ();
        BigInteger a = parameters.getG(); 

        // извлечь секретное значение
        BigInteger x = privateKeyS.getX(); int bitsQ = q.bitLength();
        
        // указать начальные условия
        BigInteger r = BigInteger.ZERO; BigInteger s = BigInteger.ZERO;
        
        // указать генератор случайных чисел
        try (Random random = new Random(rand)) 
        {
            // проверить ограничение
            while (r.signum() == 0 || s.signum() == 0)
            {
                // указать начальные условия
                BigInteger k = BigInteger.ZERO; 
                
                // проверить условие генерации
                while (k.signum() == 0 || k.compareTo(q) >= 0)
                {                
                    // сгенерировать ненулевое число
                    k = new BigInteger(bitsQ, random); 
                }
                // вычислить параметр R подписи
                r = a.modPow(k, p).mod(q);

                // вычислить параметр S подписи
                s = (k.multiply(h)).add(x.multiply(r)).mod(q);
            }
        }
        // выделить память для подписи
        int len = (bitsQ + 7) / 8 * 2; byte[] signature = new byte[len]; 

        // закодировать значения R и S
        Convert.fromBigInteger(s, Endian.BIG_ENDIAN, signature,       0, len / 2); 
        Convert.fromBigInteger(r, Endian.BIG_ENDIAN, signature, len / 2, len / 2); 
          
        return signature;
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(Factory factory, SecurityObject scope, 
        SignHash signHash, String paramOID, String hashOID, BigInteger y, 
        BigInteger x, byte[] k, byte[] hash, byte[] signature) throws Exception
    {
        // указать фабрику кодирования
        DHKeyFactory keyFactory = new DHKeyFactory(OID.GOSTR3410_1994); 
        
        // создать параметры алгоритма
        IDHParameters keyParameters = new DHNamedParameters(paramOID, hashOID, null); 
        
        // создать открытый ключ
        IPublicKey publicKey = new DHPublicKey(keyFactory, keyParameters, y); 
        
        // создать личный ключ
        try (IPrivateKey privateKey = new DHPrivateKey(
            factory, null, keyFactory.keyOID(), keyParameters, x))
        {
            // выполнить тест
            knownTest(scope, signHash, publicKey, privateKey, 
                new byte[][] { k }, null, hash, signature
            ); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритма
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Factory factory, SecurityObject scope, 
        aladdin.capi.SignHash signHash) throws Exception
    {
        // выполнить тест
        knownTest(factory, scope, signHash, OID.SIGNS_TEST, OID.HASHES_TEST, 
            new BigInteger(1, new byte[] { 
            (byte)0xEE, (byte)0x19, (byte)0x02, (byte)0xA4, 
            (byte)0x06, (byte)0x92, (byte)0xD2, (byte)0x73, 
            (byte)0xED, (byte)0xC1, (byte)0xB5, (byte)0xAD, 
            (byte)0xC5, (byte)0x5F, (byte)0x91, (byte)0x12, 
            (byte)0x8E, (byte)0x35, (byte)0xF9, (byte)0xD1, 
            (byte)0x65, (byte)0xFA, (byte)0x99, (byte)0x01, 
            (byte)0xCA, (byte)0xF0, (byte)0x0D, (byte)0x27, 
            (byte)0x01, (byte)0x8B, (byte)0xA6, (byte)0xDF, 
            (byte)0x32, (byte)0x45, (byte)0x19, (byte)0xC1, 
            (byte)0x1A, (byte)0x6E, (byte)0x27, (byte)0x25, 
            (byte)0x26, (byte)0x58, (byte)0x9C, (byte)0xD6, 
            (byte)0xE6, (byte)0xA2, (byte)0xED, (byte)0xDA, 
            (byte)0xAF, (byte)0xE1, (byte)0xC3, (byte)0x08, 
            (byte)0x12, (byte)0x59, (byte)0xBE, (byte)0x9F, 
            (byte)0xCE, (byte)0xE6, (byte)0x67, (byte)0xA2, 
            (byte)0x70, (byte)0x1F, (byte)0x43, (byte)0x52        
        }), new BigInteger(1, new byte[] { 
            (byte)0x30, (byte)0x36, (byte)0x31, (byte)0x45, 
            (byte)0x38, (byte)0x30, (byte)0x38, (byte)0x30, 
            (byte)0x34, (byte)0x36, (byte)0x30, (byte)0x45, 
            (byte)0x42, (byte)0x35, (byte)0x32, (byte)0x44, 
            (byte)0x35, (byte)0x32, (byte)0x42, (byte)0x34, 
            (byte)0x31, (byte)0x41, (byte)0x32, (byte)0x37, 
            (byte)0x38, (byte)0x32, (byte)0x43, (byte)0x31, 
            (byte)0x38, (byte)0x44, (byte)0x30, (byte)0x46,  
        }), new byte[] { 
            (byte)0x90, (byte)0xF3, (byte)0xA5, (byte)0x64, 
            (byte)0x43, (byte)0x92, (byte)0x42, (byte)0xF5, 
            (byte)0x18, (byte)0x6E, (byte)0xBB, (byte)0x22, 
            (byte)0x4C, (byte)0x8E, (byte)0x22, (byte)0x38, 
            (byte)0x11, (byte)0xB7, (byte)0x10, (byte)0x5C, 
            (byte)0x64, (byte)0xE4, (byte)0xF5, (byte)0x39, 
            (byte)0x08, (byte)0x07, (byte)0xE6, (byte)0x36, 
            (byte)0x2D, (byte)0xF4, (byte)0xC7, (byte)0x2A
        }, new byte[] {
            (byte)0x30, (byte)0x42, (byte)0x45, (byte)0x31, 
            (byte)0x36, (byte)0x41, (byte)0x45, (byte)0x34,
            (byte)0x42, (byte)0x43, (byte)0x41, (byte)0x37,
            (byte)0x45, (byte)0x33, (byte)0x36, (byte)0x43,
            (byte)0x39, (byte)0x31, (byte)0x37, (byte)0x34,
            (byte)0x45, (byte)0x34, (byte)0x31, (byte)0x44,
            (byte)0x36, (byte)0x42, (byte)0x45, (byte)0x32, 
            (byte)0x41, (byte)0x45, (byte)0x34, (byte)0x35
        }, new byte[] {
            (byte)0x3F, (byte)0x0D, (byte)0xD5, (byte)0xD4,
            (byte)0x40, (byte)0x0D, (byte)0x47, (byte)0xC0,
            (byte)0x8E, (byte)0x4C, (byte)0xE5, (byte)0x05,
            (byte)0xFF, (byte)0x74, (byte)0x34, (byte)0xB6,
            (byte)0xDB, (byte)0xF7, (byte)0x29, (byte)0x59,
            (byte)0x2E, (byte)0x37, (byte)0xC7, (byte)0x48,
            (byte)0x56, (byte)0xDA, (byte)0xB8, (byte)0x51,
            (byte)0x15, (byte)0xA6, (byte)0x09, (byte)0x55,
            (byte)0x3E, (byte)0x5F, (byte)0x89, (byte)0x5E, 
            (byte)0x27, (byte)0x6D, (byte)0x81, (byte)0xD2,
            (byte)0xD5, (byte)0x2C, (byte)0x07, (byte)0x63,
            (byte)0x27, (byte)0x0A, (byte)0x45, (byte)0x81,
            (byte)0x57, (byte)0xB7, (byte)0x84, (byte)0xC5,
            (byte)0x7A, (byte)0xBD, (byte)0xBD, (byte)0x80,
            (byte)0x7B, (byte)0xC4, (byte)0x4F, (byte)0xD4,
            (byte)0x3A, (byte)0x32, (byte)0xAC, (byte)0x06
        }); 
    }
}
