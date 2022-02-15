package aladdin.capi.stb.keyx.stb34101;
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
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа СТБ 34.101 на стороне отправителе
///////////////////////////////////////////////////////////////////////////
public class TransportKeyWrap extends aladdin.capi.TransportKeyWrap
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 

    // алгоритм шифрования ключа
    private final KeyWrap keyWrapAlgorithm; 
        
    // конструктор
    public TransportKeyWrap(KeyWrap keyWrapAlgorithm) 
    {  
        // сохранить переданные параметры
        this.keyWrapAlgorithm = RefObject.addRef(keyWrapAlgorithm); 
    } 
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить используемые ресурсы
        RefObject.release(keyWrapAlgorithm); super.onClose();        
    }
    // зашифровать ключ
    @Override public TransportKeyData wrap(AlgorithmIdentifier algorithmParameters, 
        IPublicKey publicKey, IRand rand, ISecretKey CEK) throws IOException, InvalidKeyException
    {
        // преобразовать тип ключа
        aladdin.capi.stb.stb34101.IPublicKey stbPublicKey = 
            (aladdin.capi.stb.stb34101.IPublicKey)publicKey;

        // преобразовать тип параметров
        aladdin.capi.stb.stb34101.IParameters parameters = 
            (aladdin.capi.stb.stb34101.IParameters)publicKey.parameters(); 
            
        // создать эллиптическую кривую
        Curve ec = parameters.getCurve(); BigInteger k = BigInteger.ZERO; 

        // извлечь параметры алгоритма
        BigInteger q = parameters.getOrder(); int bitsQ = q.bitLength();
            
        // создать базовую точку эллиптической кривой
        ECPoint G = parameters.getGenerator(); ECPoint Q = stbPublicKey.getW();
            
        // указать генератор случайных чисел
        try (aladdin.capi.Random random = new aladdin.capi.Random(rand)) 
        {
            // сгенерировать ненулевое число
            while(k.signum() == 0) { k = new BigInteger(bitsQ, random); } 
        }
        // выполнить вычисления
        BigInteger R = ec.multiply(G, k).getAffineX(); 
        
        // выполнить вычисления
        BigInteger Theta = ec.multiply(Q, k).getAffineX(); 
        
        // закодировать значение
        byte[] encodedR = Convert.fromBigInteger(R, ENDIAN, bitsQ / 8); 
            
        // закодировать значение
        byte[] encodedTheta = Convert.fromBigInteger(Theta, ENDIAN, bitsQ / 8); 
            
        // создать ключ шифрования ключа
        try (ISecretKey KEK = keyWrapAlgorithm.keyFactory().create(Arrays.copyOf(encodedTheta, 32)))
        {
            // зашифровать ключ
            byte[] encryptedKey = Array.concat(encodedR, keyWrapAlgorithm.wrap(rand, KEK, CEK)); 

            // вернуть зашифрованный ключ
            return new TransportKeyData(algorithmParameters, encryptedKey); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(aladdin.capi.TransportKeyWrap transportKeyWrap, 
        String paramOID,  BigInteger d, byte[] k, 
        byte[] I, byte[] CEK, byte[] result) throws Exception
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
        // указать случайные данные
        byte[][] random = new byte[][] { k, I }; 
        
        // указать используемые параметры
        AlgorithmIdentifier algorithmParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.stb.OID.STB34101_BIGN_KEYTRANSPORT), Null.INSTANCE
        ); 
        // выполнить тест
        knownTest(transportKeyWrap, algorithmParameters, 
            publicKey, random, CEK, result
        ); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритма
    ////////////////////////////////////////////////////////////////////////////
    public static void test(aladdin.capi.TransportKeyWrap transportKeyWrap) throws Exception
    {
        knownTest(transportKeyWrap, 
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
            (byte)0xD5, (byte)0xAA, (byte)0x88, (byte)0x1C,
            (byte)0x6F, (byte)0x8E, (byte)0x1B, (byte)0xBE, 
            (byte)0x2F, (byte)0xD4, (byte)0xA3, (byte)0xF9, 
            (byte)0xA8, (byte)0x62, (byte)0x13, (byte)0xAD, 
            (byte)0xA1, (byte)0x26, (byte)0x4F, (byte)0xEF, 
            (byte)0x7A, (byte)0xB0, (byte)0x4A, (byte)0xBD, 
            (byte)0x20, (byte)0x7C, (byte)0x61, (byte)0x47, 
            (byte)0x13, (byte)0xD9, (byte)0x51, (byte)0x0F 
        }, new byte[] {
            (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
            (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
            (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
            (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
        }, new byte[] {
            (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
            (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
            (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
            (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
            (byte)0x85, (byte)0x04
        }, new byte[] {
            (byte)0x9B, (byte)0x4E, (byte)0xA6, (byte)0x69, 
            (byte)0xDA, (byte)0xBD, (byte)0xF1, (byte)0x00, 
            (byte)0xA7, (byte)0xD4, (byte)0xB6, (byte)0xE6, 
            (byte)0xEB, (byte)0x76, (byte)0xEE, (byte)0x52, 
            (byte)0x51, (byte)0x91, (byte)0x25, (byte)0x31, 
            (byte)0xF4, (byte)0x26, (byte)0x75, (byte)0x0A, 
            (byte)0xAC, (byte)0x8A, (byte)0x9D, (byte)0xBB, 
            (byte)0x51, (byte)0xC5, (byte)0x4D, (byte)0x8D, 
            (byte)0xEB, (byte)0x92, (byte)0x89, (byte)0xB5, 
            (byte)0x0A, (byte)0x46, (byte)0x95, (byte)0x2D, 
            (byte)0x05, (byte)0x31, (byte)0x86, (byte)0x1E, 
            (byte)0x45, (byte)0xA8, (byte)0x81, (byte)0x4B, 
            (byte)0x00, (byte)0x8F, (byte)0xDC, (byte)0x65, 
            (byte)0xDE, (byte)0x9F, (byte)0xF1, (byte)0xFA, 
            (byte)0x2A, (byte)0x1F, (byte)0x16, (byte)0xB6, 
            (byte)0xA2, (byte)0x80, (byte)0xE9, (byte)0x57, 
            (byte)0xA8, (byte)0x14
        }); 
    }
}

