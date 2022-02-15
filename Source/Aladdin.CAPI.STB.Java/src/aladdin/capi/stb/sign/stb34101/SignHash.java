package aladdin.capi.stb.sign.stb34101;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.capi.*;
import aladdin.capi.ec.*;
import aladdin.util.*; 
import java.math.*;
import java.security.spec.*; 
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////
// Алгоритм подписи СТБ 34.101
///////////////////////////////////////////////////////////////////////
public class SignHash extends aladdin.capi.SignHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 

    // алгоритм хэширования
    private final Hash hashAlgorithm; 
        
    // конструктор
    public SignHash(Hash hashAlgorithm) 
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
    @Override public byte[] sign(aladdin.capi.IPrivateKey privateKey, 
        IRand rand, AlgorithmIdentifier hashParameters, byte[] hash) throws IOException
    {
        // преобразовать тип ключа
        aladdin.capi.stb.stb34101.IPrivateKey stbPrivateKey = 
            (aladdin.capi.stb.stb34101.IPrivateKey)privateKey;

        // получить параметры алгоритма
        aladdin.capi.stb.stb34101.IParameters parameters = 
            (aladdin.capi.stb.stb34101.IParameters)privateKey.parameters(); 

        // создать эллиптическую кривую
        Curve ec = parameters.getCurve(); ECPoint G = parameters.getGenerator();

        // извлечь параметры алгоритма
        BigInteger q = parameters.getOrder(); int bitsQ = q.bitLength();

        // указать поле для вычислений
        FieldFp field = new FieldFp(q);
            
        // создать экспоненту
        BigInteger H = Convert.toBigInteger(hash, ENDIAN).mod(q);  

        // извлечь секретное значение
        BigInteger d = stbPrivateKey.getS(); BigInteger k = BigInteger.ZERO; 

        // указать генератор случайных чисел
        try (aladdin.capi.Random random = new aladdin.capi.Random(rand)) 
        {
            // сгенерировать ненулевое число
            while(k.signum() == 0) { k = new BigInteger(bitsQ, random); }
        }
        // выполнить вычисления
        BigInteger R = ec.multiply(G, k).getAffineX(); 
        
        // закодировать значение
        byte[] encodedR = Convert.fromBigInteger(R, ENDIAN, bitsQ / 8); 

        // создать буфер для хэширования
        hash = Array.concat(hashParameters.algorithm().encoded(), encodedR, hash); 
            
        // выполнить хэширование
        hash = hashAlgorithm.hashData(hash, 0, hash.length); 
            
        // закодировать данные
        byte[] S0 = Arrays.copyOf(hash, bitsQ / 16); 
            
        // вычислить S0 + 2^l
        BigInteger S01 = Convert.toBigInteger(Array.concat(S0, new byte[] { 1 }), ENDIAN); 
            
        // выполнить вычисления
        BigInteger S1 = field.subtract(field.subtract(k, H), field.product(S01, d)); 
            
        // вернуть значение подписи
        return Array.concat(S0, Convert.fromBigInteger(S1, ENDIAN, bitsQ / 8)); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(Factory factory, SecurityObject scope, 
        aladdin.capi.SignHash signHash, Hash hbelt, String paramOID, 
        BigInteger d, byte[] k, byte[] M, byte[] signature) throws Exception
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
        // создать личный ключ
        try (IPrivateKey privateKey = new aladdin.capi.stb.stb34101.PrivateKey(
            factory, null, publicKey.keyOID(), parameters, d))
        {
            // закодировать параметры алгоритма хэширования
            AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.stb.OID.STB34101_BELT_HASH), Null.INSTANCE
            ); 
            // вычислить хэш-значение
            byte[] hash = hbelt.hashData(M, 0, M.length); 
            
            // выполнить тест
            knownTest(scope, signHash, publicKey, privateKey, 
                new byte[][] { k }, hashParameters, hash, signature
            ); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритма
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Factory factory, SecurityObject scope, 
        aladdin.capi.SignHash signHash, Hash hbelt) throws Exception
    {
        knownTest(factory, scope, signHash, hbelt, 
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
            (byte)0xD2, (byte)0xB7, (byte)0x08, (byte)0xA3, 
            (byte)0x7A, (byte)0xA7, (byte)0x33, (byte)0x5C, 
            (byte)0xE1, (byte)0x1C, (byte)0x46, (byte)0x3C, 
            (byte)0x48, (byte)0xEC, (byte)0xD6, (byte)0x3E, 
            (byte)0x2C, (byte)0x74, (byte)0xFA, (byte)0xE0, 
            (byte)0xE7, (byte)0x3D, (byte)0xF2, (byte)0x21, 
            (byte)0xAD, (byte)0x11, (byte)0x58, (byte)0xCD, 
            (byte)0xB2, (byte)0x74, (byte)0x0E, (byte)0x4C 
        }, new byte[] {
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
    }
}
