package aladdin.capi.ansi.keyx.rsa.oaep;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.capi.ansi.derive.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм зашифрования RSA OAEP
///////////////////////////////////////////////////////////////////////////
public class Encipherment extends aladdin.capi.ansi.keyx.rsa.Encipherment
{
    private final Hash       hashAlgorithm;	// алгоритм хэширования
    private final PRF        maskAlgorithm;	// функция генерации маски
    private final byte[]     label;			// дополнительная метка
    
    // способ возведения в степень
    private final aladdin.capi.Encipherment rawEncipherment; 
    
    // конструктор
    public Encipherment(Hash hashAlgorithm, byte[] label) 
    { 
        // сохранить переданные параметры
        this(null, hashAlgorithm, label); 
    }
    // конструктор
    public Encipherment(Hash hashAlgorithm, PRF maskAlgorithm, byte[] label) 
    { 
        // сохранить переданные параметры
        this(null, hashAlgorithm, maskAlgorithm, label); 
    }
    // конструктор
    public Encipherment(aladdin.capi.Encipherment rawEncipherment, 
        Hash hashAlgorithm, byte[] label)
    {
        // сохранить переданные параметры
        this.rawEncipherment = RefObject.addRef(rawEncipherment); 
        
        // сохранить переданные параметры
        this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
        
        // создать алгоритм маскирования
        this.maskAlgorithm = new MGF1(hashAlgorithm); this.label = label;
    }
    // конструктор
    public Encipherment(aladdin.capi.Encipherment rawEncipherment, 
        Hash hashAlgorithm, PRF maskAlgorithm, byte[] label)
    {
        // сохранить переданные параметры
        this.rawEncipherment = RefObject.addRef(rawEncipherment); 
        
        // сохранить переданные параметры
        this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
        this.maskAlgorithm	= RefObject.addRef(maskAlgorithm); this.label = label;
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(rawEncipherment); RefObject.release(maskAlgorithm);
        
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); super.onClose();            
    }
    // закодировать данные
    @Override protected byte[] encode(IRand rand, byte[] data, int bits) throws IOException
    {
        // закодировать данные
        return Encoding.encode(hashAlgorithm, maskAlgorithm, label, rand, data, (bits + 7) / 8); 
    }
    // способ возведения в степень
    @Override protected byte[] power(
        aladdin.capi.ansi.rsa.IPublicKey publicKey, byte[] data) throws IOException
    {
        // выполнить возведение в степень
        if (rawEncipherment == null) return super.power(publicKey, data); 
        
        // выполнить возведение в степень
        return rawEncipherment.encrypt(publicKey, null, data); 
    }
}
