package aladdin.capi.ansi.sign.rsa.pss;
import aladdin.*; 
import aladdin.asn1.iso.*;
import aladdin.capi.*; 
import aladdin.capi.ansi.derive.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи RSA PSS
///////////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.ansi.sign.rsa.VerifyHash
{
    private final Hash  hashAlgorithm;	// алгоритм хэширования
    private final PRF	maskAlgorithm;	// функция генерации маски
    private final int   saltLength;		// размер salt-значения
    private final byte  trailerField;	// завершающий байт
    
    // способ возведения в степень
    private final aladdin.capi.Encipherment rawEncipherment; 
    
    // конструктор
    public VerifyHash(Hash hashAlgorithm, int saltLength, byte trailerField)
    {
        // сохранить переданные параметры
        this(null, hashAlgorithm, saltLength, trailerField); 
    }
    // конструктор
    public VerifyHash(Hash hashAlgorithm, PRF maskAlgorithm, int saltLength, byte trailerField)
    {
        // сохранить переданные параметры
        this(null, hashAlgorithm, maskAlgorithm, saltLength, trailerField); 
    }
    // конструктор
    public VerifyHash(aladdin.capi.Encipherment rawEncipherment, 
        Hash hashAlgorithm, int saltLength, byte trailerField)
    {
        // сохранить переданные параметры
        this.rawEncipherment = RefObject.addRef(rawEncipherment); 
        
        // сохранить переданные параметры
        this.hashAlgorithm = RefObject.addRef(hashAlgorithm);
        
        // создать алгоритм маскирования
        this.maskAlgorithm = new MGF1(hashAlgorithm);
        
        // сохранить переданные параметры
        this.saltLength	= saltLength; this.trailerField = trailerField;
    }
    // конструктор
    public VerifyHash(aladdin.capi.Encipherment rawEncipherment, 
        Hash hashAlgorithm, PRF maskAlgorithm, int saltLength, byte trailerField)
    {
        // сохранить переданные параметры
        this.rawEncipherment = RefObject.addRef(rawEncipherment); 
        
        // сохранить переданные параметры
        this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
        this.maskAlgorithm	= RefObject.addRef(maskAlgorithm);
        
        // сохранить переданные параметры
        this.saltLength	= saltLength; this.trailerField = trailerField;
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException 
    {
        // освободить выделенные ресурсы
        RefObject.release(rawEncipherment); RefObject.release(maskAlgorithm);
        
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); super.onClose();
    }
    // проверить подпись
    @Override protected void check(byte[] encoded, int bits, 
        AlgorithmIdentifier hashAlgorithm, byte[] hash) throws IOException, SignatureException
    {
        // проверить корректность подписи
        Encoding.decode(this.hashAlgorithm, maskAlgorithm, 
            trailerField, encoded, bits - 1, saltLength, hash
        );  
    }
    // способ возведения в степень
    @Override protected byte[] power(aladdin.capi.ansi.rsa.IPublicKey publicKey, 
        byte[] signature) throws IOException
    {
        // выполнить возведение в степень
        if (rawEncipherment == null) return super.power(publicKey, signature); 
        
        // выполнить возведение в степень
        return rawEncipherment.encrypt(publicKey, null, signature); 
    }
}
