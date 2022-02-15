package aladdin.capi.ansi.keyx.ecdh;
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.ansi.x962.*; 
import aladdin.capi.*; 
import aladdin.capi.derive.*; 
import aladdin.capi.ansi.derive.*; 
import aladdin.math.*; 
import java.security.*; 
import java.security.spec.*; 
import java.io.*; 
import java.math.BigInteger;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа Elliptic Curve Diffie-Hellman
///////////////////////////////////////////////////////////////////////////
public class KeyAgreement extends aladdin.capi.KeyAgreement
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 

    private final KeyDerive             keyDerive;          // алгоритм наследования ключа
    private final AlgorithmIdentifier   keyWrapParameters;  // параметры алгоритма шифрования ключа
    private final boolean               useCofactor;        // признак дополнительного умножения
    
    // конструктор
    public KeyAgreement(boolean useCofactor, 
        KeyDerive keyDerive, AlgorithmIdentifier keyWrapParameters) 
    { 
        // сохранить переданные параметры
        this.keyDerive = RefObject.addRef(keyDerive); 
            
        // сохранить переданные параметры
        this.useCofactor = useCofactor; this.keyWrapParameters = keyWrapParameters; 
    } 
    // конструктор
    public KeyAgreement(boolean useCofactor, 
        Hash hashAlgorithm, AlgorithmIdentifier keyWrapParameters) 
    { 
        // сохранить переданные параметры
        this.keyDerive = new X963KDF(hashAlgorithm); 
            
        // сохранить переданные параметры
        this.useCofactor = useCofactor; this.keyWrapParameters = keyWrapParameters; 
    } 
    // конструктор
    public KeyAgreement(boolean useCofactor) 
    { 
        // сохранить переданные параметры
        this.keyDerive = new NOKDF(ENDIAN); 
            
        // сохранить переданные параметры
        this.useCofactor = useCofactor; this.keyWrapParameters = null;   
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
        // преобразовать тип данных
        aladdin.capi.ansi.x962.IPrivateKey ecPrivateKey = 
            (aladdin.capi.ansi.x962.IPrivateKey)privateKey; 
        aladdin.capi.ansi.x962.IPublicKey  ecPublicKey  = 
            (aladdin.capi.ansi.x962.IPublicKey )publicKey; 

        // получить параметры алгоритма
        aladdin.capi.ansi.x962.IParameters ecParameters = 
            (aladdin.capi.ansi.x962.IParameters)privateKey.parameters(); 
            
        // получить параметры эллиптической кривой
        aladdin.capi.ec.Curve ec = ecParameters.getCurve(); 
            
        // вычислить точку на эллиптической кривой
        ECPoint P = ec.multiply(ecPublicKey.getW(), ecPrivateKey.getS()); 
            
        // выполнить дополнительное умножение
        if (useCofactor) P = ec.multiply(P, BigInteger.valueOf(ecParameters.getCofactor()));
        
        // при наличии параметров шифрования
        if (keyWrapParameters != null)
        {
            // закодировать случайные данные
            OctetString entityUInfo = (random != null) ? new OctetString(random) : null; 
        
            // закодировать размер ключа в битах
            OctetString suppPubInfo = new OctetString(Convert.fromInt32(keySize * 8, ENDIAN));
            
            // объединить закодированные данные
            SharedInfo sharedInfo = new SharedInfo(
                keyWrapParameters, entityUInfo, null, suppPubInfo, null
            ); 
            // получить закодированное представление
            random = sharedInfo.encoded(); 
        }
        // определить размер закодированного представления
        int cb = (ec.getField().getFieldSize() + 7) / 8; 
        
        // закодировать координату точки
        byte[] encodedX = Convert.fromBigInteger(P.getAffineX(), ENDIAN, cb); 
        
        // закодировать координату точки
        try (ISecretKey z = keyDerive.keyFactory().create(encodedX))
        {
            // выполнить наследование ключа
            return keyDerive.deriveKey(z, random, keyFactory, keySize); 
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
    }
}
