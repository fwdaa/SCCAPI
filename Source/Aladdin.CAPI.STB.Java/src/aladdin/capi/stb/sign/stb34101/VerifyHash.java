package aladdin.capi.stb.sign.stb34101;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.capi.*;
import aladdin.capi.ec.*;
import aladdin.util.*; 
import java.security.*;
import java.security.spec.*;
import java.math.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи СТБ 34.101
///////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.VerifyHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 

    // алгоритм хэширования
    private final Hash hashAlgorithm; 
        
    // конструктор
    public VerifyHash(Hash hashAlgorithm) 
    { 
        // сохранить переданные параметры
        this.hashAlgorithm = RefObject.addRef(hashAlgorithm); 
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); super.onClose(); 
    }
    @Override public void verify(aladdin.capi.IPublicKey publicKey, 
        AlgorithmIdentifier hashParameters, byte[] hash, byte[] signature) 
        throws IOException, SignatureException
    {
        // преобразовать тип ключа
        aladdin.capi.stb.stb34101.IPublicKey stbPublicKey = 
            (aladdin.capi.stb.stb34101.IPublicKey)publicKey;

        // получить параметры алгоритма
        aladdin.capi.stb.stb34101.IParameters parameters = 
            (aladdin.capi.stb.stb34101.IParameters)publicKey.parameters(); 

        // создать эллиптическую кривую
        Curve ec = parameters.getCurve(); 

        // извлечь параметры алгоритма
        BigInteger q = parameters.getOrder(); int bitsQ = q.bitLength();

        // указать поле для вычислений
        FieldFp field = new FieldFp(q);
            
        // создать экспоненту
        BigInteger H = Convert.toBigInteger(hash, ENDIAN).mod(q);  

        // создать базовую точку эллиптической кривой
        ECPoint G = parameters.getGenerator(); ECPoint Q = stbPublicKey.getW();
            
        // проверить размер подписи
        int len = signature.length; if (len != 3 * (bitsQ / 16))
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
        // выделить память для закодированных значений S0 и S1
        byte[] encodedS0 = new byte[1 + len / 3]; 
        byte[] encodedS1 = new byte[2 * len / 3];

        // извлечь закодированные значения S и R
        System.arraycopy(signature,       0, encodedS0, 0,     len / 3);
        System.arraycopy(signature, len / 3, encodedS1, 0, 2 * len / 3);
            
        // выполнить сложение S0 и 2^l
        encodedS0[len / 3] = 1; 
            
        // раскодировать большие числа
        BigInteger S0 = Convert.toBigInteger(encodedS0, ENDIAN);
        BigInteger S1 = Convert.toBigInteger(encodedS1, ENDIAN); 
            
        // проверить значение S1
        if (S1.compareTo(q) >= 0) throw new SignatureException();
            
        // вычислить (S1 + H) mod q
        S1 = field.add(S1, H); 
            
        // вычислить кратную точку
        ECPoint R = ec.multiply_sum(G, S1, Q, S0); 
            
        // проверить значение кратной точки
        if (R == ECPoint.POINT_INFINITY) throw new SignatureException();
            
        // закодировать значение кратной точки
        byte[] encodedR = Convert.fromBigInteger(R.getAffineX(), ENDIAN, bitsQ / 8); 

        // создать буфер для хэширования
        hash = Array.concat(hashParameters.algorithm().encoded(), encodedR, hash); 
            
        // выполнить хэширование
        hash = hashAlgorithm.hashData(hash, 0, hash.length); 
            
        // сравнить хэш-значения
        if (!Array.equals(encodedS0, 0, hash, 0, len / 3))
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(aladdin.capi.VerifyHash verifyHash, 
        Hash hbelt, String paramOID, BigInteger d, byte[] M, byte[] signature) throws Exception
    {
        // указать фабрику алгоритмов
        aladdin.capi.stb.stb34101.KeyFactory keyFactory = 
            new aladdin.capi.stb.stb34101.KeyFactory(
                aladdin.asn1.stb.OID.STB34101_BIGN_PUBKEY
        ); 
        // получить параметры алгоритма
        aladdin.capi.stb.stb34101.IParameters parameters = 
            keyFactory.decodeParameters(new ObjectIdentifier(paramOID));
        
		// создать открытый ключ
		IPublicKey publicKey = new aladdin.capi.stb.stb34101.PublicKey(
            keyFactory, parameters, 
            parameters.getCurve().multiply(parameters.getGenerator(), d)
        );
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.stb.OID.STB34101_BELT_HASH), Null.INSTANCE
        ); 
        // вычислить хэш-значение
        byte[] hash = hbelt.hashData(M, 0, M.length); 

        // проверить подпись хэш-значения
        knownTest(verifyHash, publicKey, hashParameters, hash, signature); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритма
    ////////////////////////////////////////////////////////////////////////////
    public static void test(aladdin.capi.VerifyHash verifyHash, Hash hbelt) throws Exception
    {
        knownTest(verifyHash, hbelt, 
            aladdin.asn1.stb.OID.STB34101_BIGN_CURVE256_V1, 
            new BigInteger(1, new byte[] {
            (byte)0x69, (byte)0xE2, (byte)0x73, (byte)0xC2, 
            (byte)0x5F, (byte)0x23, (byte)0x79, (byte)0x0C, 
            (byte)0x9E, (byte)0x42, (byte)0x32, (byte)0x07, 
            (byte)0xED, (byte)0x1F, (byte)0x28, (byte)0x34, 
            (byte)0x18, (byte)0xF2, (byte)0x74, (byte)0x9C, 
            (byte)0x32, (byte)0xF0, (byte)0x33, (byte)0x45, 
            (byte)0x67, (byte)0x39, (byte)0x73, (byte)0x4B, 
            (byte)0xB8, (byte)0xB5, (byte)0x66, (byte)0x1F 
        }), new byte[] {
            (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
            (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
            (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
            (byte)0x58 
        }, new byte[] {
            (byte)0xE3, (byte)0x6B, (byte)0x7F, (byte)0x03, 
            (byte)0x77, (byte)0xAE, (byte)0x4C, (byte)0x52, 
            (byte)0x40, (byte)0x27, (byte)0xC3, (byte)0x87, 
            (byte)0xFA, (byte)0xDF, (byte)0x1B, (byte)0x20, 
            (byte)0xCE, (byte)0x72, (byte)0xF1, (byte)0x53, 
            (byte)0x0B, (byte)0x71, (byte)0xF2, (byte)0xB5, 
            (byte)0xFD, (byte)0x3A, (byte)0x8C, (byte)0x58, 
            (byte)0x4F, (byte)0xE2, (byte)0xE1, (byte)0xAE,
            (byte)0xD2, (byte)0x00, (byte)0x82, (byte)0xE3, 
            (byte)0x0C, (byte)0x8A, (byte)0xF6, (byte)0x50, 
            (byte)0x11, (byte)0xF4, (byte)0xFB, (byte)0x54, 
            (byte)0x64, (byte)0x9D, (byte)0xFD, (byte)0x3D            
        }); 
        knownTest(verifyHash, hbelt, 
            aladdin.asn1.stb.OID.STB34101_BIGN_CURVE256_V1, 
            new BigInteger(1, new byte[] {
            (byte)0x69, (byte)0xE2, (byte)0x73, (byte)0xC2, 
            (byte)0x5F, (byte)0x23, (byte)0x79, (byte)0x0C, 
            (byte)0x9E, (byte)0x42, (byte)0x32, (byte)0x07, 
            (byte)0xED, (byte)0x1F, (byte)0x28, (byte)0x34, 
            (byte)0x18, (byte)0xF2, (byte)0x74, (byte)0x9C, 
            (byte)0x32, (byte)0xF0, (byte)0x33, (byte)0x45, 
            (byte)0x67, (byte)0x39, (byte)0x73, (byte)0x4B, 
            (byte)0xB8, (byte)0xB5, (byte)0x66, (byte)0x1F 
        }), new byte[] {
            (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
            (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
            (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
            (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
            (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
            (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
            (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
            (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D, 
            (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
            (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
            (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
            (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
        }, new byte[] {
            (byte)0x47, (byte)0xA6, (byte)0x3C, (byte)0x8B, 
            (byte)0x9C, (byte)0x93, (byte)0x6E, (byte)0x94, 
            (byte)0xB5, (byte)0xFA, (byte)0xB3, (byte)0xD9, 
            (byte)0xCB, (byte)0xD7, (byte)0x83, (byte)0x66, 
            (byte)0x29, (byte)0x0F, (byte)0x32, (byte)0x10, 
            (byte)0xE1, (byte)0x63, (byte)0xEE, (byte)0xC8, 
            (byte)0xDB, (byte)0x4E, (byte)0x92, (byte)0x1E, 
            (byte)0x84, (byte)0x79, (byte)0xD4, (byte)0x13, 
            (byte)0x8F, (byte)0x11, (byte)0x2C, (byte)0xC2, 
            (byte)0x3E, (byte)0x6D, (byte)0xCE, (byte)0x65, 
            (byte)0xEC, (byte)0x5F, (byte)0xF2, (byte)0x1D, 
            (byte)0xF4, (byte)0x23, (byte)0x1C, (byte)0x28
        }); 
    }
}
