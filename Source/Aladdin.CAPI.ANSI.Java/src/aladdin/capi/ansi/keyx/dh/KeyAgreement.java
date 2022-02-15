package aladdin.capi.ansi.keyx.dh;
import aladdin.*; 
import aladdin.math.*;
import aladdin.capi.*; 
import aladdin.capi.derive.*; 
import aladdin.capi.ansi.derive.*;
import java.math.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа Diffie-Hellman
///////////////////////////////////////////////////////////////////////////
public class KeyAgreement extends aladdin.capi.KeyAgreement
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // алгоритм наследования ключа
    private final KeyDerive keyDerive; 
    
    // конструктор
    public KeyAgreement(KeyDerive keyDerive) 
    { 
        // сохранить переданные параметры
        this.keyDerive = RefObject.addRef(keyDerive); 
    }
    // конструктор
    public KeyAgreement() { keyDerive = new NOKDF(ENDIAN); }
    
    // конструктор
    public KeyAgreement(Hash hashAlgorithm, String keyWrapOID) 
    { 
        // создать алгоритм наследования ключа
        keyDerive = new X942KDF(hashAlgorithm, keyWrapOID); 
    } 
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException 
    {
        // освободить используемые ресурсы
        RefObject.release(keyDerive); super.onClose();            
    }
    // сгенерировать случайные данные
    @Override public byte[] generate(IParameters parameters, IRand rand) throws IOException
    {
        // проверить необходимость генерации
        if (keyDerive instanceof NOKDF) return null; 
        
        // сгенерировать случайные данные
        byte[] random = new byte[64]; rand.generate(random, 0, 64); return random;   
    }
    // наследовать ключ
    @Override public ISecretKey deriveKey(IPrivateKey privateKey, 
        IPublicKey publicKey, byte[] random, 
        SecretKeyFactory keyFactory, int keySize) throws IOException
    {
        // закодировать секретное число
        try (ISecretKey ZZ = keyDerive.keyFactory().create(deriveKey(privateKey, publicKey)))
        {
            // выполнить наследование ключа
            return keyDerive.deriveKey(ZZ, random, keyFactory, keySize); 
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
    }
    protected byte[] deriveKey(IPrivateKey privateKey, IPublicKey publicKey) throws IOException
    {
        // преобразовать тип данных
        aladdin.capi.ansi.x942.IPrivateKey privateKeyX = 
            (aladdin.capi.ansi.x942.IPrivateKey)privateKey; 
        aladdin.capi.ansi.x942.IPublicKey  publicKeyX  = 
            (aladdin.capi.ansi.x942.IPublicKey )publicKey; 

        // получить параметры алгоритма
        aladdin.capi.ansi.x942.IParameters parameters = 
            (aladdin.capi.ansi.x942.IParameters)privateKey.parameters(); 

        // вычислить секретное число
        BigInteger Z = publicKeyX.getY().modPow(privateKeyX.getX(), parameters.getP()); 

        // закодировать секретное число
        return Convert.fromBigInteger(Z, ENDIAN, (parameters.getP().bitLength() + 7) / 8);
    }
}
