package aladdin.capi.gost.sign.gostr3410;
import aladdin.capi.gost.gostr3410.*; 
import aladdin.math.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*;
import aladdin.capi.ec.*; 
import java.security.*;
import java.security.spec.*;
import java.math.*;

///////////////////////////////////////////////////////////////////////
// Проверка подписи хэш-значения ГОСТ Р 34.10-2001, 2012
///////////////////////////////////////////////////////////////////////
public class ECVerifyHash extends VerifyHash
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
        BigInteger s = Convert.toBigInteger(signature,       0, len / 2, Endian.BIG_ENDIAN); 
        BigInteger r = Convert.toBigInteger(signature, len / 2, len / 2, Endian.BIG_ENDIAN); 
        
        // преобразовать тип ключа
        IECPublicKey publicKeyS = (IECPublicKey)publicKey;

        // получить параметры алгоритма
        IECParameters parameters = (IECParameters)publicKeyS.parameters(); 

        // извлечь параметры алгоритма
        Curve ec = parameters.getCurve(); BigInteger q = parameters.getOrder();

        // извлечь параметры алгоритма
        ECPoint P = parameters.getGenerator(); ECPoint Q = publicKeyS.getW();
        
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
        BigInteger e = Convert.toBigInteger(hash, Endian.LITTLE_ENDIAN).mod(q);  

        // обработать частный случай
        if (e.signum() == 0) e = BigInteger.ONE; 
            
        // создать обратную экспоненту
        BigInteger v = e.modInverse(q);  

        // выполнить вычисления
        BigInteger z1 = s.multiply(v).mod(q);
        BigInteger z2 = q.subtract(r).multiply(v).mod(q);
        
        // выполнить вычисления
        ECPoint sum = ec.multiply_sum(P, z1, Q, z2); 

        // проверить корректность подписи
        if (sum == ECPoint.POINT_INFINITY) throw new SignatureException();
        
        // проверить корректность подписи
        if (!sum.getAffineX().mod(q).equals(r)) throw new SignatureException();
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(VerifyHash verifyHash, 
        String keyOID, String paramOID, String hashOID, 
        BigInteger qx, BigInteger qy, byte[] hash, byte[] signature) throws Exception
    {
        // указать фабрику кодирования
        ECKeyFactory keyFactory = new ECKeyFactory(keyOID); 
        
        // создать параметры алгоритма
        IECParameters keyParameters = ECNamedParameters2001.create(paramOID, hashOID, null); 
        
        // создать открытый ключ
        IPublicKey publicKey = new ECPublicKey(
            keyFactory, keyParameters, new ECPoint(qx, qy)
        ); 
        // проверить подпись хэш-значения
        knownTest(verifyHash, publicKey, null, hash, signature); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритма
    ////////////////////////////////////////////////////////////////////////////
    public static void test256(aladdin.capi.VerifyHash verifyHash, 
        String keyOID, String hashOID) throws Exception
    {
        // выполнить тест
        knownTest(verifyHash, keyOID, OID.ECC_SIGNS_TEST, hashOID, 
            new BigInteger(1, new byte[] { 
            (byte)0x7F, (byte)0x2B, (byte)0x49, (byte)0xE2,
            (byte)0x70, (byte)0xDB, (byte)0x6D, (byte)0x90,
            (byte)0xD8, (byte)0x59, (byte)0x5B, (byte)0xEC,
            (byte)0x45, (byte)0x8B, (byte)0x50, (byte)0xC5,
            (byte)0x85, (byte)0x85, (byte)0xBA, (byte)0x1D,
            (byte)0x4E, (byte)0x9B, (byte)0x78, (byte)0x8F,
            (byte)0x66, (byte)0x89, (byte)0xDB, (byte)0xD8,
            (byte)0xE5, (byte)0x6F, (byte)0xD8, (byte)0x0B
        }), new BigInteger(1, new byte[] { 
            (byte)0x26, (byte)0xF1, (byte)0xB4, (byte)0x89,
            (byte)0xD6, (byte)0x70, (byte)0x1D, (byte)0xD1,
            (byte)0x85, (byte)0xC8, (byte)0x41, (byte)0x3A,
            (byte)0x97, (byte)0x7B, (byte)0x3C, (byte)0xBB,
            (byte)0xAF, (byte)0x64, (byte)0xD1, (byte)0xC5,
            (byte)0x93, (byte)0xD2, (byte)0x66, (byte)0x27,
            (byte)0xDF, (byte)0xFB, (byte)0x10, (byte)0x1A,
            (byte)0x87, (byte)0xFF, (byte)0x77, (byte)0xDA
        }), new byte[] {
            (byte)0xE5, (byte)0x3E, (byte)0x04, (byte)0x2B,
            (byte)0x67, (byte)0xE6, (byte)0xEC, (byte)0x67,
            (byte)0x8E, (byte)0x2E, (byte)0x02, (byte)0xB1,
            (byte)0x2A, (byte)0x03, (byte)0x52, (byte)0xCE,
            (byte)0x1F, (byte)0xC6, (byte)0xEE, (byte)0xE0,
            (byte)0x52, (byte)0x9C, (byte)0xC0, (byte)0x88,
            (byte)0x11, (byte)0x9A, (byte)0xD8, (byte)0x72,
            (byte)0xB3, (byte)0xC1, (byte)0xFB, (byte)0x2D
        }, new byte[] {
            (byte)0x01, (byte)0x45, (byte)0x6C, (byte)0x64,
            (byte)0xBA, (byte)0x46, (byte)0x42, (byte)0xA1,
            (byte)0x65, (byte)0x3C, (byte)0x23, (byte)0x5A,
            (byte)0x98, (byte)0xA6, (byte)0x02, (byte)0x49,
            (byte)0xBC, (byte)0xD6, (byte)0xD3, (byte)0xF7,
            (byte)0x46, (byte)0xB6, (byte)0x31, (byte)0xDF,
            (byte)0x92, (byte)0x80, (byte)0x14, (byte)0xF6,
            (byte)0xC5, (byte)0xBF, (byte)0x9C, (byte)0x40, 
            (byte)0x41, (byte)0xAA, (byte)0x28, (byte)0xD2, 
            (byte)0xF1, (byte)0xAB, (byte)0x14, (byte)0x82, 
            (byte)0x80, (byte)0xCD, (byte)0x9E, (byte)0xD5, 
            (byte)0x6F, (byte)0xED, (byte)0xA4, (byte)0x19, 
            (byte)0x74, (byte)0x05, (byte)0x35, (byte)0x54, 
            (byte)0xA4, (byte)0x27, (byte)0x67, (byte)0xB8, 
            (byte)0x3A, (byte)0xD0, (byte)0x43, (byte)0xFD, 
            (byte)0x39, (byte)0xDC, (byte)0x04, (byte)0x93 
        }); 
    }
    public static void test512(aladdin.capi.VerifyHash verifyHash) throws Exception
    {
        // выполнить тест
        knownTest(verifyHash, OID.GOSTR3410_2012_512, 
            OID.ECC_TC26_2012_512T, OID.GOSTR3411_2012_512, 
            new BigInteger(1, new byte[] { 
            (byte)0x11, (byte)0x5D, (byte)0xC5, (byte)0xBC, 
            (byte)0x96, (byte)0x76, (byte)0x0C, (byte)0x7B, 
            (byte)0x48, (byte)0x59, (byte)0x8D, (byte)0x8A, 
            (byte)0xB9, (byte)0xE7, (byte)0x40, (byte)0xD4, 
            (byte)0xC4, (byte)0xA8, (byte)0x5A, (byte)0x65, 
            (byte)0xBE, (byte)0x33, (byte)0xC1, (byte)0x81, 
            (byte)0x5B, (byte)0x5C, (byte)0x32, (byte)0x0C, 
            (byte)0x85, (byte)0x46, (byte)0x21, (byte)0xDD, 
            (byte)0x5A, (byte)0x51, (byte)0x58, (byte)0x56, 
            (byte)0xD1, (byte)0x33, (byte)0x14, (byte)0xAF, 
            (byte)0x69, (byte)0xBC, (byte)0x5B, (byte)0x92, 
            (byte)0x4C, (byte)0x8B, (byte)0x4D, (byte)0xDF, 
            (byte)0xF7, (byte)0x5C, (byte)0x45, (byte)0x41, 
            (byte)0x5C, (byte)0x1D, (byte)0x9D, (byte)0xD9, 
            (byte)0xDD, (byte)0x33, (byte)0x61, (byte)0x2C, 
            (byte)0xD5, (byte)0x30, (byte)0xEF, (byte)0xE1
        }), new BigInteger(1, new byte[] { 
            (byte)0x37, (byte)0xC7, (byte)0xC9, (byte)0x0C, 
            (byte)0xD4, (byte)0x0B, (byte)0x0F, (byte)0x56, 
            (byte)0x21, (byte)0xDC, (byte)0x3A, (byte)0xC1, 
            (byte)0xB7, (byte)0x51, (byte)0xCF, (byte)0xA0, 
            (byte)0xE2, (byte)0x63, (byte)0x4F, (byte)0xA0, 
            (byte)0x50, (byte)0x3B, (byte)0x3D, (byte)0x52, 
            (byte)0x63, (byte)0x9F, (byte)0x5D, (byte)0x7F, 
            (byte)0xB7, (byte)0x2A, (byte)0xFD, (byte)0x61, 
            (byte)0xEA, (byte)0x19, (byte)0x94, (byte)0x41, 
            (byte)0xD9, (byte)0x43, (byte)0xFF, (byte)0xE7, 
            (byte)0xF0, (byte)0xC7, (byte)0x0A, (byte)0x27, 
            (byte)0x59, (byte)0xA3, (byte)0xCD, (byte)0xB8, 
            (byte)0x4C, (byte)0x11, (byte)0x4E, (byte)0x1F, 
            (byte)0x93, (byte)0x39, (byte)0xFD, (byte)0xF2, 
            (byte)0x7F, (byte)0x35, (byte)0xEC, (byte)0xA9, 
            (byte)0x36, (byte)0x77, (byte)0xBE, (byte)0xEC
        }), new byte[] {
            (byte)0x8C, (byte)0x5B, (byte)0x07, (byte)0x72,
            (byte)0x29, (byte)0x7D, (byte)0x77, (byte)0xC6,
            (byte)0x4F, (byte)0x0C, (byte)0x56, (byte)0x1D,
            (byte)0xDB, (byte)0xDE, (byte)0x7A, (byte)0x40,
            (byte)0x5A, (byte)0x5D, (byte)0x7C, (byte)0x64,
            (byte)0x6C, (byte)0x97, (byte)0x39, (byte)0x43,
            (byte)0x41, (byte)0xF4, (byte)0x93, (byte)0x65,
            (byte)0x53, (byte)0xEE, (byte)0x84, (byte)0x71,
            (byte)0x91, (byte)0xC5, (byte)0xB0, (byte)0x35,
            (byte)0x70, (byte)0x14, (byte)0x1D, (byte)0xA7,
            (byte)0x33, (byte)0xC5, (byte)0x70, (byte)0xC1,
            (byte)0xF9, (byte)0xB6, (byte)0x09, (byte)0x1B,
            (byte)0x53, (byte)0xAB, (byte)0x8D, (byte)0x4D,
            (byte)0x7C, (byte)0x4A, (byte)0x4F, (byte)0x5C,
            (byte)0x61, (byte)0xE0, (byte)0xC9, (byte)0xAC,
            (byte)0xCF, (byte)0xF3, (byte)0x54, (byte)0x37
        }, new byte[] {
            (byte)0x10, (byte)0x81, (byte)0xB3, (byte)0x94, 
            (byte)0x69, (byte)0x6F, (byte)0xFE, (byte)0x8E, 
            (byte)0x65, (byte)0x85, (byte)0xE7, (byte)0xA9, 
            (byte)0x36, (byte)0x2D, (byte)0x26, (byte)0xB6, 
            (byte)0x32, (byte)0x5F, (byte)0x56, (byte)0x77, 
            (byte)0x8A, (byte)0xAD, (byte)0xBC, (byte)0x08, 
            (byte)0x1C, (byte)0x0B, (byte)0xFB, (byte)0xE9, 
            (byte)0x33, (byte)0xD5, (byte)0x2F, (byte)0xF5, 
            (byte)0x82, (byte)0x3C, (byte)0xE2, (byte)0x88, 
            (byte)0xE8, (byte)0xC4, (byte)0xF3, (byte)0x62, 
            (byte)0x52, (byte)0x60, (byte)0x80, (byte)0xDF, 
            (byte)0x7F, (byte)0x70, (byte)0xCE, (byte)0x40, 
            (byte)0x6A, (byte)0x6E, (byte)0xEB, (byte)0x1F, 
            (byte)0x56, (byte)0x91, (byte)0x9C, (byte)0xB9, 
            (byte)0x2A, (byte)0x98, (byte)0x53, (byte)0xBD, 
            (byte)0xE7, (byte)0x3E, (byte)0x5B, (byte)0x4A, 
            (byte)0x2F, (byte)0x86, (byte)0xFA, (byte)0x60, 
            (byte)0xA0, (byte)0x81, (byte)0x09, (byte)0x1A, 
            (byte)0x23, (byte)0xDD, (byte)0x79, (byte)0x5E, 
            (byte)0x1E, (byte)0x3C, (byte)0x68, (byte)0x9E, 
            (byte)0xE5, (byte)0x12, (byte)0xA3, (byte)0xC8, 
            (byte)0x2E, (byte)0xE0, (byte)0xDC, (byte)0xC2, 
            (byte)0x64, (byte)0x3C, (byte)0x78, (byte)0xEE, 
            (byte)0xA8, (byte)0xFC, (byte)0xAC, (byte)0xD3, 
            (byte)0x54, (byte)0x92, (byte)0x55, (byte)0x84, 
            (byte)0x86, (byte)0xB2, (byte)0x0F, (byte)0x1C, 
            (byte)0x9E, (byte)0xC1, (byte)0x97, (byte)0xC9, 
            (byte)0x06, (byte)0x99, (byte)0x85, (byte)0x02, 
            (byte)0x60, (byte)0xC9, (byte)0x3B, (byte)0xCB, 
            (byte)0xCD, (byte)0x9C, (byte)0x5C, (byte)0x33, 
            (byte)0x17, (byte)0xE1, (byte)0x93, (byte)0x44, 
            (byte)0xE1, (byte)0x73, (byte)0xAE, (byte)0x36                    
        }); 
    }
}