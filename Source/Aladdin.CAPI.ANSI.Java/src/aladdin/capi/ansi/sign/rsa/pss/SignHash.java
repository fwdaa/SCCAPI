package aladdin.capi.ansi.sign.rsa.pss;
import aladdin.*; 
import aladdin.asn1.iso.*;
import aladdin.capi.*; 
import aladdin.capi.ansi.derive.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA PSS
///////////////////////////////////////////////////////////////////////////
public class SignHash extends aladdin.capi.ansi.sign.rsa.SignHash
{
    private final Hash  hashAlgorithm;	// алгоритм хэширования
    private final PRF	maskAlgorithm;	// функция генерации маски
    private final int   saltLength;		// размер salt-значения
    private final byte  trailerField;	// завершающий байт
    
    // способ возведения в степень
    private final aladdin.capi.Decipherment rawDecipherment; 
    
    // конструктор
    public SignHash(Hash hashAlgorithm, int saltLength, byte trailerField)
    {
        // сохранить переданные параметры
        this(null, hashAlgorithm, saltLength, trailerField); 
    }
    // конструктор
    public SignHash(Hash hashAlgorithm, PRF maskAlgorithm, int saltLength, byte trailerField)
    {
        // сохранить переданные параметры
        this(null, hashAlgorithm, maskAlgorithm, saltLength, trailerField); 
    }
    // конструктор
    public SignHash(aladdin.capi.Decipherment rawDecipherment, 
        Hash hashAlgorithm, int saltLength, byte trailerField)
    {
        // сохранить переданные параметры
        this.rawDecipherment = RefObject.addRef(rawDecipherment); 
        
        // сохранить переданные параметры
        this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
        
        // создать алгоритм маскирования
        this.maskAlgorithm	= new MGF1(hashAlgorithm);
        
        // сохранить переданные параметры
        this.saltLength	= saltLength; this.trailerField	= trailerField;
    }
    // конструктор
    public SignHash(aladdin.capi.Decipherment rawDecipherment, 
        Hash hashAlgorithm, PRF maskAlgorithm, int saltLength, byte trailerField)
    {
        // сохранить переданные параметры
        this.rawDecipherment = RefObject.addRef(rawDecipherment); 
        
        // сохранить переданные параметры
        this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
        this.maskAlgorithm	= RefObject.addRef(maskAlgorithm);
        
        // сохранить переданные параметры
        this.saltLength	= saltLength; this.trailerField	= trailerField;
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException 
    {
        // освободить выделенные ресурсы
        RefObject.release(rawDecipherment); RefObject.release(maskAlgorithm);
        
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); super.onClose();            
    }
    // закодировать данные
    @Override protected byte[] encode(IRand rand, 
        AlgorithmIdentifier hashAlgorithm, byte[] hash, int bits) throws IOException
    {
        return Encoding.encode(rand, this.hashAlgorithm, 
            maskAlgorithm, trailerField, bits - 1, saltLength, hash
        ); 
    }
    // способ возведения в степень
    @Override protected byte[] power(aladdin.capi.ansi.rsa.IPrivateKey privateKey, 
        IRand rand, byte[] hash) throws IOException
    {
        // выполнить возведение в степень
        if (rawDecipherment == null) return super.power(privateKey, rand, hash); 
        
        // выполнить возведение в степень
        return rawDecipherment.decrypt(privateKey, hash); 
    }
}
