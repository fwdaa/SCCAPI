package aladdin.capi.stb.keyx.stb34101;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.capi.*; 
import aladdin.capi.ec.*; 
import java.security.*;
import java.security.spec.*;
import java.math.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа СТБ 34.101 на стороне получателе
///////////////////////////////////////////////////////////////////////////
public class TransportKeyUnwrap extends aladdin.capi.TransportKeyUnwrap
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
        
    // алгоритм шифрования ключа
    private final KeyWrap keyWrapAlgorithm; 
        
    // конструктор
    public TransportKeyUnwrap(KeyWrap keyWrapAlgorithm) 
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
    @Override public ISecretKey unwrap(aladdin.capi.IPrivateKey privateKey, 
        TransportKeyData transportData, SecretKeyFactory keyFactory) throws IOException
    {
        // преобразовать тип ключа
        aladdin.capi.stb.stb34101.IPrivateKey stbPrivateKey = 
            (aladdin.capi.stb.stb34101.IPrivateKey)privateKey; 
            
        // преобразовать тип параметров
        aladdin.capi.stb.stb34101.IParameters parameters = 
            (aladdin.capi.stb.stb34101.IParameters)privateKey.parameters(); 
            
        // создать эллиптическую кривую
        CurveFp ec = parameters.getCurve(); FieldFp field = ec.getField(); 
        
        // извлечь параметры алгоритма
        BigInteger q = parameters.getOrder(); int bitsQ = q.bitLength();
            
        // извлечь секретное значение
        BigInteger d = stbPrivateKey.getS(); byte[] encryptedKey = transportData.encryptedKey; 
            
        // проверить размер зашифрованного ключа
        if (encryptedKey.length < bitsQ / 8 + 32) throw new IOException(); 
            
        // раскодировать значение xR
        BigInteger xR = Convert.toBigInteger(encryptedKey, 0, bitsQ / 8, ENDIAN); 
            
        // проверить корректность значения xR
        if (xR.compareTo(field.getP()) >= 0) throw new IOException(); 
            
        // вычислить xR^3 + axR + b
        BigInteger check = field.add(ec.getB(), 
            field.product(xR, field.add(ec.getA(), field.sqr(xR)))
        ); 
        // вычислить (p + 1) / 4
        BigInteger exponent = field.getP().add(BigInteger.ONE).shiftRight(2); 
            
        // выполнить возведение в степень
        BigInteger yR = field.power(check, exponent);  
            
        // проверить коррректность данных
        if (field.sqr(yR).compareTo(check) != 0) throw new IOException(); 
            
        // построить точку эллиптической кривой
        ECPoint R = new ECPoint(xR, yR); R = ec.multiply(R, d); 
            
        // выполнить вычисления
        byte[] Theta = Convert.fromBigInteger(R.getAffineX(), ENDIAN, bitsQ / 8); 

        // извлечь зашифрованный ключ
        encryptedKey = Arrays.copyOfRange(encryptedKey, bitsQ / 8, encryptedKey.length); 
            
        // создать ключ шифрования ключа
        try (ISecretKey KEK = keyWrapAlgorithm.keyFactory().create(Arrays.copyOf(Theta, 32)))  
        {
            // расшифровать ключ
            return keyWrapAlgorithm.unwrap(KEK, encryptedKey, keyFactory); 
        } 
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    private static void knownTest(Factory factory, SecurityObject scope, 
        aladdin.capi.TransportKeyUnwrap transportKeyUnwrap, String paramOID, 
        BigInteger d, byte[] CEK, byte[] result) throws Exception
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
            factory, null, keyFactory.keyOID(), parameters, d))
        {
            // указать параметры алгоритма
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.stb.OID.STB34101_BELT_KEYWRAP_256), Null.INSTANCE
            );
            // закодировать параметры алгоритма 
            AlgorithmIdentifier algParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.stb.OID.STB34101_BIGN_KEYTRANSPORT), 
                wrapParameters
            );
            // указать значение для проверки
            TransportKeyData check = new TransportKeyData(algParameters, result); 
            
            // выполнить тест
            knownTest(scope, transportKeyUnwrap, publicKey, privateKey, CEK, check); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритма
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Factory factory, SecurityObject scope, 
        aladdin.capi.TransportKeyUnwrap transportKeyUnwrap) throws Exception
    {
        knownTest(factory, scope, transportKeyUnwrap, 
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
        knownTest(factory, scope, transportKeyUnwrap, 
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
            (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D
        }, new byte[] {
            (byte)0x48, (byte)0x56, (byte)0x09, (byte)0x3A, 
            (byte)0x0F, (byte)0x6C, (byte)0x13, (byte)0x01, 
            (byte)0x5F, (byte)0xC8, (byte)0xE1, (byte)0x5F, 
            (byte)0x1B, (byte)0x23, (byte)0xA7, (byte)0x62, 
            (byte)0x02, (byte)0xD2, (byte)0xF4, (byte)0xBA, 
            (byte)0x6E, (byte)0x5E, (byte)0xC5, (byte)0x2B, 
            (byte)0x78, (byte)0x65, (byte)0x84, (byte)0x77, 
            (byte)0xF6, (byte)0x48, (byte)0x6D, (byte)0xE6, 
            (byte)0x87, (byte)0xAF, (byte)0xAE, (byte)0xEA, 
            (byte)0x0E, (byte)0xF7, (byte)0xBC, (byte)0x13, 
            (byte)0x26, (byte)0xA7, (byte)0xDC, (byte)0xE7, 
            (byte)0xA1, (byte)0x0B, (byte)0xA1, (byte)0x0E, 
            (byte)0x3F, (byte)0x91, (byte)0xC0, (byte)0x12, 
            (byte)0x60, (byte)0x44, (byte)0xB2, (byte)0x22, 
            (byte)0x67, (byte)0xBF, (byte)0x30, (byte)0xBD, 
            (byte)0x6F, (byte)0x1D, (byte)0xA2, (byte)0x9E, 
            (byte)0x06, (byte)0x47, (byte)0xCF, (byte)0x39, 
            (byte)0xC1, (byte)0xD5, (byte)0x9A, (byte)0x56, 
            (byte)0xBB, (byte)0x01, (byte)0x94, (byte)0xE0, 
            (byte)0xF4, (byte)0xF8, (byte)0xA2, (byte)0xBB
        }); 
    }   
}
