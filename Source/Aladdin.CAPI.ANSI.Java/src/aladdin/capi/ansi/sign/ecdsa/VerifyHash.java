package aladdin.capi.ansi.sign.ecdsa;
import aladdin.math.*;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkix.*;
import aladdin.asn1.ansi.x962.*;
import aladdin.capi.*;
import aladdin.capi.ec.*;
import java.security.*;
import java.security.spec.*;
import java.math.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи ECDSA
///////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.VerifyHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
        
    @Override public void verify(aladdin.capi.IPublicKey publicKey, 
        AlgorithmIdentifier hashParameters, byte[] hash, 
        byte[] signature) throws IOException, SignatureException
    {
        // получить параметры алгоритма
        aladdin.capi.ansi.x962.IParameters ecParameters = 
            (aladdin.capi.ansi.x962.IParameters)publicKey.parameters(); 

        // преобразовать тип ключа
        aladdin.capi.ansi.x962.IPublicKey ecPublicKey = 
            (aladdin.capi.ansi.x962.IPublicKey)publicKey;

        // указать эллиптическую кривую
        aladdin.capi.ec.Curve ec = ecParameters.getCurve(); 
            
        // извлечь параметры алгоритма
        BigInteger n = ecParameters.getOrder(); FieldFp fn = new FieldFp(n); 
        
        // определить требуемый размер в битах
        int bitsN = n.bitLength(); hash = hash.clone();

        // выделить первые биты хэш-значения
        if (hash.length > (bitsN + 7) / 8) hash = Arrays.copyOf(hash, (bitsN + 7) / 8); 
            
        // при необходимости
        if (hash.length == (bitsN + 7) / 8 && (bitsN % 8) != 0) 
        {
            // обнулить неиспользуемые биты
            hash[0] &= (1 << (bitsN % 8)) - 1; 
        }
        // преобразовать хэш-значение в число
        BigInteger e = Convert.toBigInteger(hash, ENDIAN).mod(n);  
        
        // раскодировать подпись
        IEncodable encodedSignature = Encodable.decode(signature);
                
        // в зависимости от типа подписи
        if (encodedSignature.tag().equals(Tag.SEQUENCE))
        {
            // преобразовать тип подписи
            ECDSASigValue decodedSignature = new ECDSASigValue(encodedSignature); 
                
            // извлечь значения r и s
            BigInteger r = decodedSignature.r().value(); 
            BigInteger s = decodedSignature.s().value(); 

            // проверить корректность r и s
            if (r.signum() == 0 || r.compareTo(n) >= 0) throw new SignatureException(); 
            if (s.signum() == 0 || s.compareTo(n) >= 0) throw new SignatureException(); 
                    
            // вычислить u1 = es^{-1} mod n
            BigInteger s1 = fn.invert(s); BigInteger u1 = fn.product(e, s1); 

            // вычислить u2 = rs^{-1} mod n
            BigInteger u2 = fn.product(r, s1); 
                    
            // вычислить R = u1G + u2Q
            ECPoint R = ec.multiply_sum(ecParameters.getGenerator(), u1, ecPublicKey.getW(), u2); 
                    
            // проверить на бесконечную точку
            if (R == ECPoint.POINT_INFINITY) throw new SignatureException();
                    
            // преобразовать элемент поля в число
            BigInteger v = R.getAffineX().mod(n); 
                  
            // проверить совпадение
            if (!v.equals(r)) throw new SignatureException();  
        }
        // в зависимости от типа подписи
        else if (encodedSignature.tag().equals(Tag.context(0)))
        {
            // преобразовать тип подписи
            ECDSAFullR decodedSignature = new ECDSAFullR(
                Encodable.decode(encodedSignature.content())
            ); 
            // извлечь значение R 
            ECPoint R = ec.decode(decodedSignature.r().value()); 
                    
            // преобразовать элемент поля в число
            BigInteger r = R.getAffineX().mod(n); 
                    
            // извлечь значение s 
            BigInteger s = decodedSignature.s().value(); 

            // проверить корректность r и s
            if (r.signum() == 0 || r.compareTo(n) >= 0) throw new SignatureException(); 
            if (s.signum() == 0 || s.compareTo(n) >= 0) throw new SignatureException(); 
                    
            // вычислить eG + rQ
            ECPoint right = ec.multiply_sum(ecParameters.getGenerator(), e, ecPublicKey.getW(), r); 
                    
            // проверить корректность подписи
            if (!ec.multiply(R, s).equals(right)) throw new SignatureException(); 
        }
        // при ошибке выбросить исключение
        else throw new IOException(); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(aladdin.capi.VerifyHash verifyHash, 
        Hash sha1, String paramOID, byte[] encodedQ, 
        byte[] message, BigInteger r, BigInteger s) throws Exception
    {
        // указать фабрику алгоритмов
        aladdin.capi.KeyFactory keyFactory = new aladdin.capi.ansi.x962.KeyFactory(
            aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY
        ); 
        // закодировать открытый ключ
        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(
                new ObjectIdentifier(keyFactory.keyOID()), new ObjectIdentifier(paramOID)
            ), new BitString(encodedQ)
        ); 
        // создать открытый ключ
        aladdin.capi.IPublicKey publicKey = keyFactory.decodePublicKey(publicKeyInfo); 
        
        // указать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
        ); 
        // вычислить хэш-значение
        byte[] hash = sha1.hashData(message, 0, message.length); 

        // закодировать подпись
        ECDSASigValue signature = new ECDSASigValue(new Integer(r), new Integer(s), null, null); 
        
        // проверить подпись хэш-значения
        knownTest(verifyHash, publicKey, hashParameters, hash, signature.encoded()); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритма
    ////////////////////////////////////////////////////////////////////////////
    public static void test(aladdin.capi.VerifyHash verifyHash, Hash sha1) throws Exception
    {
        knownTest(verifyHash, sha1, 
            aladdin.asn1.ansi.OID.X962_CURVES_C2TNB191V1, 
            new byte[] {
            (byte)0x04, (byte)0x5D, (byte)0xE3, (byte)0x7E, 
            (byte)0x75, (byte)0x6B, (byte)0xD5, (byte)0x5D, 
            (byte)0x72, (byte)0xE3, (byte)0x76, (byte)0x8C, 
            (byte)0xB3, (byte)0x96, (byte)0xFF, (byte)0xEB, 
            (byte)0x96, (byte)0x26, (byte)0x14, (byte)0xDE, 
            (byte)0xA4, (byte)0xCE, (byte)0x28, (byte)0xA2, 
            (byte)0xE7, (byte)0x55, (byte)0xC0, (byte)0xE0, 
            (byte)0xE0, (byte)0x2F, (byte)0x5F, (byte)0xB1, 
            (byte)0x32, (byte)0xCA, (byte)0xF4, (byte)0x16, 
            (byte)0xEF, (byte)0x85, (byte)0xB2, (byte)0x29, 
            (byte)0xBB, (byte)0xB8, (byte)0xE1, (byte)0x35, 
            (byte)0x20, (byte)0x03, (byte)0x12, (byte)0x5B, 
            (byte)0xA1        
        }, new byte[] {
            (byte)0x61, (byte)0x62, (byte)0x63
        }, new BigInteger(1, new byte[] {
            (byte)0x03, (byte)0x8E, (byte)0x5A, (byte)0x11, 
            (byte)0xFB, (byte)0x55, (byte)0xE4, (byte)0xC6, 
            (byte)0x54, (byte)0x71, (byte)0xDC, (byte)0xD4, 
            (byte)0x99, (byte)0x84, (byte)0x52, (byte)0xB1, 
            (byte)0xE0, (byte)0x2D, (byte)0x8A, (byte)0xF7, 
            (byte)0x09, (byte)0x9B, (byte)0xB9, (byte)0x30, 
        }), new BigInteger(1, new byte[] {
            (byte)0x0C, (byte)0x9A, (byte)0x08, (byte)0xC3, 
            (byte)0x44, (byte)0x68, (byte)0xC2, (byte)0x44, 
            (byte)0xB4, (byte)0xE5, (byte)0xD6, (byte)0xB2, 
            (byte)0x1B, (byte)0x3C, (byte)0x68, (byte)0x36, 
            (byte)0x28, (byte)0x07, (byte)0x41, (byte)0x60, 
            (byte)0x20, (byte)0x32, (byte)0x8B, (byte)0x6E, 
        })); 
        knownTest(verifyHash, sha1, 
            aladdin.asn1.ansi.OID.X962_CURVES_C2TNB239V1, 
            new byte[] {
            (byte)0x04, (byte)0x58, (byte)0x94, (byte)0x60, 
            (byte)0x9C, (byte)0xCE, (byte)0xCF, (byte)0x9A, 
            (byte)0x92, (byte)0x53, (byte)0x3F, (byte)0x63, 
            (byte)0x0D, (byte)0xE7, (byte)0x13, (byte)0xA9, 
            (byte)0x58, (byte)0xE9, (byte)0x6C, (byte)0x97, 
            (byte)0xCC, (byte)0xB8, (byte)0xF5, (byte)0xAB, 
            (byte)0xB5, (byte)0xA6, (byte)0x88, (byte)0xA2, 
            (byte)0x38, (byte)0xDE, (byte)0xED, (byte)0x6D, 
            (byte)0xC2, (byte)0xD9, (byte)0xD0, (byte)0xC9, 
            (byte)0x4E, (byte)0xBF, (byte)0xB7, (byte)0xD5, 
            (byte)0x26, (byte)0xBA, (byte)0x6A, (byte)0x61, 
            (byte)0x76, (byte)0x41, (byte)0x75, (byte)0xB9, 
            (byte)0x9C, (byte)0xB6, (byte)0x01, (byte)0x1E, 
            (byte)0x20, (byte)0x47, (byte)0xF9, (byte)0xF0, 
            (byte)0x67, (byte)0x29, (byte)0x3F, (byte)0x57, 
            (byte)0xF5        
        }, new byte[] {
            (byte)0x61, (byte)0x62, (byte)0x63
        }, new BigInteger(1, new byte[] {
            (byte)0x03, (byte)0x21, (byte)0x0D, (byte)0x71, 
            (byte)0xEF, (byte)0x6C, (byte)0x10, (byte)0x15, 
            (byte)0x7C, (byte)0x0D, (byte)0x10, (byte)0x53, 
            (byte)0xDF, (byte)0xF9, (byte)0x3E, (byte)0x8B, 
            (byte)0x08, (byte)0x5F, (byte)0x1E, (byte)0x9B, 
            (byte)0xC2, (byte)0x24, (byte)0x01, (byte)0xF7, 
            (byte)0xA2, (byte)0x47, (byte)0x98, (byte)0xA6, 
            (byte)0x3C, (byte)0x00, 
        }), new BigInteger(1, new byte[] {
            (byte)0x1C, (byte)0x8C, (byte)0x43, (byte)0x43, 
            (byte)0xA8, (byte)0xEC, (byte)0xBF, (byte)0x7C, 
            (byte)0x4D, (byte)0x4E, (byte)0x48, (byte)0xF7, 
            (byte)0xD7, (byte)0x6D, (byte)0x56, (byte)0x58, 
            (byte)0xBC, (byte)0x02, (byte)0x7C, (byte)0x77, 
            (byte)0x08, (byte)0x6E, (byte)0xC8, (byte)0xB1, 
            (byte)0x00, (byte)0x97, (byte)0xDE, (byte)0xB3, 
            (byte)0x07, (byte)0xD6, 
        })); 
        knownTest(verifyHash, sha1, 
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME192V1, 
            new byte[] {
            (byte)0x02, (byte)0x62, (byte)0xB1, (byte)0x2D, 
            (byte)0x60, (byte)0x69, (byte)0x0C, (byte)0xDC, 
            (byte)0xF3, (byte)0x30, (byte)0xBA, (byte)0xBA, 
            (byte)0xB6, (byte)0xE6, (byte)0x97, (byte)0x63, 
            (byte)0xB4, (byte)0x71, (byte)0xF9, (byte)0x94, 
            (byte)0xDD, (byte)0x70, (byte)0x2D, (byte)0x16, 
            (byte)0xA5        
        }, new byte[] {
            (byte)0x61, (byte)0x62, (byte)0x63
        }, new BigInteger(1, new byte[] {
            (byte)0x88, (byte)0x50, (byte)0x52, (byte)0x38, 
            (byte)0x0F, (byte)0xF1, (byte)0x47, (byte)0xB7, 
            (byte)0x34, (byte)0xC3, (byte)0x30, (byte)0xC4, 
            (byte)0x3D, (byte)0x39, (byte)0xB2, (byte)0xC4, 
            (byte)0xA8, (byte)0x9F, (byte)0x29, (byte)0xB0, 
            (byte)0xF7, (byte)0x49, (byte)0xFE, (byte)0xAD, 
        }), new BigInteger(1, new byte[] {
            (byte)0xE9, (byte)0xEC, (byte)0xC7, (byte)0x81, 
            (byte)0x06, (byte)0xDE, (byte)0xF8, (byte)0x2B, 
            (byte)0xF1, (byte)0x07, (byte)0x0C, (byte)0xF1, 
            (byte)0xD4, (byte)0xD8, (byte)0x04, (byte)0xC3, 
            (byte)0xCB, (byte)0x39, (byte)0x00, (byte)0x46, 
            (byte)0x95, (byte)0x1D, (byte)0xF6, (byte)0x86, 
        })); 
        knownTest(verifyHash, sha1, 
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME239V1, 
            new byte[] {
            (byte)0x02, (byte)0x5B, (byte)0x6D, (byte)0xC5, 
            (byte)0x3B, (byte)0xC6, (byte)0x1A, (byte)0x25, 
            (byte)0x48, (byte)0xFF, (byte)0xB0, (byte)0xF6, 
            (byte)0x71, (byte)0x47, (byte)0x2D, (byte)0xE6, 
            (byte)0xC9, (byte)0x52, (byte)0x1A, (byte)0x9D, 
            (byte)0x2D, (byte)0x25, (byte)0x34, (byte)0xE6, 
            (byte)0x5A, (byte)0xBF, (byte)0xCB, (byte)0xD5, 
            (byte)0xFE, (byte)0x0C, (byte)0x70        
        }, new byte[] {
            (byte)0x61, (byte)0x62, (byte)0x63
        }, new BigInteger(1, new byte[] {
            (byte)0x2C, (byte)0xB7, (byte)0xF3, (byte)0x68, 
            (byte)0x03, (byte)0xEB, (byte)0xB9, (byte)0xC4, 
            (byte)0x27, (byte)0xC5, (byte)0x8D, (byte)0x82, 
            (byte)0x65, (byte)0xF1, (byte)0x1F, (byte)0xC5, 
            (byte)0x08, (byte)0x47, (byte)0x47, (byte)0x13, 
            (byte)0x30, (byte)0x78, (byte)0xFC, (byte)0x27, 
            (byte)0x9D, (byte)0xE8, (byte)0x74, (byte)0xFB, 
            (byte)0xEC, (byte)0xB0, 
        }), new BigInteger(1, new byte[] {
            (byte)0x2E, (byte)0xEA, (byte)0xE9, (byte)0x88, 
            (byte)0x10, (byte)0x4E, (byte)0x9C, (byte)0x22, 
            (byte)0x34, (byte)0xA3, (byte)0xC2, (byte)0xBE, 
            (byte)0xB1, (byte)0xF5, (byte)0x3B, (byte)0xFA, 
            (byte)0x5D, (byte)0xC1, (byte)0x1F, (byte)0xF3, 
            (byte)0x6A, (byte)0x87, (byte)0x5D, (byte)0x1E, 
            (byte)0x3C, (byte)0xCB, (byte)0x1F, (byte)0x7E, 
            (byte)0x45, (byte)0xCF, 
        })); 
    }
}
