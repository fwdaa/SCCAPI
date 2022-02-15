package aladdin.capi.gost.keyx.gostr3410;
import aladdin.capi.gost.gostr3410.*; 
import aladdin.*; 
import aladdin.math.*; 
import aladdin.asn1.gost.*;
import aladdin.capi.*; 
import aladdin.capi.derive.*; 
import java.math.*; 
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////////
public class DHKeyAgreement extends KeyAgreement
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // алгоритм наследования ключа
    private final KeyDerive keyDerive; 
    
    // конструктор
    public DHKeyAgreement(KeyDerive keyDerive)
    {
        // сохранить переданные параметры
        this.keyDerive = RefObject.addRef(keyDerive); 
    }
    // конструктор
    public DHKeyAgreement() { this.keyDerive = new NOKDF(ENDIAN); } 
    
    // деструктор
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
        RefObject.release(keyDerive); super.onClose();
    }
    // сгенерировать случайные данные
    @Override public byte[] generate(
        aladdin.capi.IParameters parameters, IRand rand) throws IOException  
    { 
        // сгенерировать случайные данные
        byte[] random = new byte[8]; rand.generate(random, 0, random.length);

        // проверить наличие ненулевых байтов
        if (random[0] == 0) random[0] ^= 0x1; return random;  
    }
    // наследовать ключ
    @Override public ISecretKey deriveKey(aladdin.capi.IPrivateKey privateKey, 
        aladdin.capi.IPublicKey publicKey, byte[] random, 
        SecretKeyFactory keyFactory, int keySize) throws IOException 
    {
        // преобразовать тип параметров
        IDHParameters parameters = (IDHParameters) privateKey.parameters(); 

        // преобразовать тип данных
        IDHPrivateKey privateKeyX = (IDHPrivateKey)privateKey; 
        IDHPublicKey  publicKeyX  = (IDHPublicKey )publicKey;

        // извлечь параметры алгоритма
        BigInteger p = parameters.getP(); BigInteger y = publicKeyX.getY();

        // выполнить математические операции
        BigInteger k = y.modPow(privateKeyX.getX(), p);
            
        // выделить память для точки эллиптической кривой
        byte[] encodedK = new byte[(p.bitLength() + 7) / 8];  
            
        // закодировать координаты точки
        Convert.fromBigInteger(k, ENDIAN, encodedK, 0, encodedK.length); 

        // создать алгоритм хэширования
        try (Hash hashAlgorithm = createHashAlgorithm(privateKey, keySize))
        {
            // получить ключ как хэш-значение
            try (ISecretKey key = keyDerive.keyFactory().create(
                hashAlgorithm.hashData(encodedK, 0, encodedK.length)))
            {
                // выполнить наследование ключа
                return keyDerive.deriveKey(key, random, keyFactory, keySize); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new IOException(e); }
        }
    }
    // создать алгоритм хэширования
    protected Hash createHashAlgorithm(IPrivateKey privateKey, int keySize) throws IOException
    {
        // преобразовать тип параметров
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)privateKey.parameters(); 
        
        // получить именованные параметры алгоритма
        GOSTR3411ParamSet1994 namedParameters = 
            GOSTR3411ParamSet1994.parameters(parameters.hashOID());

        // раскодировать таблицу подстановок
        byte[] sbox = GOST28147SBoxReference.decodeSBox(namedParameters.huz()); 

        // создать алгоритм хэширования
        return new aladdin.capi.gost.hash.GOSTR3411_1994(
            sbox, namedParameters.h0().value(), false
        );
    }
}
