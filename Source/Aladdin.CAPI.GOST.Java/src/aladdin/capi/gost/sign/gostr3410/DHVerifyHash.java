package aladdin.capi.gost.sign.gostr3410;
import aladdin.capi.gost.gostr3410.*; 
import aladdin.math.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*;
import java.security.*;
import java.math.*;

///////////////////////////////////////////////////////////////////////
// Проверка подписи хэш-значения ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////
public class DHVerifyHash extends VerifyHash
{
    @Override public void verify(aladdin.capi.IPublicKey publicKey, 
        AlgorithmIdentifier hashParameters, byte[] hash, 
        byte[] signature) throws SignatureException
    {
        // проверить размер подписи
        int len = signature.length; if ((len % 2) != 0)
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
        // извлечь значения S и R
        BigInteger s = Convert.toBigInteger(signature,       0, len / 2, Endian.BIG_ENDIAN); 
        BigInteger r = Convert.toBigInteger(signature, len / 2, len / 2, Endian.BIG_ENDIAN); 
        
        // получить параметры алгоритма
        IDHParameters parameters = (IDHParameters)publicKey.parameters(); 
        // преобразовать тип ключа
        IDHPublicKey publicKeyS = (IDHPublicKey)publicKey;

        // извлечь параметры алгоритма
        BigInteger p = parameters.getP(); BigInteger q = parameters.getQ();
        BigInteger a = parameters.getG(); BigInteger y = publicKeyS.getY();
            
        // проверить корректность R
        if (r.signum() == 0 || r.compareTo(q) >= 0)
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
        // проверить корректность S
        if (s.signum() == 0 || s.compareTo(q) >= 0)
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
        // создать экспоненту
        BigInteger h = Convert.toBigInteger(hash, Endian.LITTLE_ENDIAN);
            
        // проверить значение 
        if (h.signum() == 0) h = BigInteger.ONE; 

        // создать обратную экспоненту
        BigInteger v = h.modInverse(q); 
        
        // указать используемое поле
        aladdin.math.Fp.Field field = new aladdin.math.Fp.Field(p); 

        // выполнить вычисления
        BigInteger z1 = s.multiply(v).mod(q);
        BigInteger z2 = q.subtract(r).multiply(v).mod(q);
            
        // проверить корректность подписи
        if (!field.power_product(a, z1, y, z2).mod(q).equals(r))
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(VerifyHash verifyHash, 
        String paramOID, String hashOID, BigInteger y, 
        byte[] hash, byte[] signature) throws Exception
    {
        // указать фабрику кодирования
        DHKeyFactory keyFactory = new DHKeyFactory(OID.GOSTR3410_1994); 
        
        // создать параметры алгоритма
        IDHParameters keyParameters = new DHNamedParameters(paramOID, hashOID, null); 
        
        // создать открытый ключ
        IPublicKey publicKey = new DHPublicKey(keyFactory, keyParameters, y); 
        
        // проверить подпись хэш-значения
        knownTest(verifyHash, publicKey, null, hash, signature); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритма
    ////////////////////////////////////////////////////////////////////////////
    public static void test(VerifyHash verifyHash) throws Exception
    {
        // выполнить тест
        knownTest(verifyHash, OID.SIGNS_TEST, OID.HASHES_TEST, 
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
        }), new byte[] {
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
