package aladdin.capi.ansi.keyx.rsa.oaep;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.capi.ansi.derive.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм расшифрования RSA OAEP
///////////////////////////////////////////////////////////////////////////
public class Decipherment extends aladdin.capi.ansi.keyx.rsa.Decipherment
{
    private final Hash   hashAlgorithm;	// алгоритм хэширования
    private final PRF    maskAlgorithm;	// функция генерации маски
    private final byte[] label;			// дополнительная метка
    
    // способ возведения в степень
    private final aladdin.capi.Decipherment rawDecipherment; 
    
    // конструктор
    public Decipherment(Hash hashAlgorithm, byte[] label)
    {
        // сохранить переданные параметры
        this(null, hashAlgorithm, label); 
    }
    // конструктор
    public Decipherment(Hash hashAlgorithm, PRF maskAlgorithm, byte[] label)
    {
        // сохранить переданные параметры
        this(null, hashAlgorithm, maskAlgorithm, label); 
    }
    // конструктор
    public Decipherment(aladdin.capi.Decipherment rawDecipherment, 
        Hash hashAlgorithm, byte[] label)
    {
        // сохранить переданные параметры
        this.rawDecipherment = RefObject.addRef(rawDecipherment); 
        
        // сохранить переданные параметры
        this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
        
        // создать алгоритм маскирования
        this.maskAlgorithm	= new MGF1(hashAlgorithm); this.label = label;
    }
    // конструктор
    public Decipherment(aladdin.capi.Decipherment rawDecipherment, 
        Hash hashAlgorithm, PRF maskAlgorithm, byte[] label)
    {
        // сохранить переданные параметры
        this.rawDecipherment = RefObject.addRef(rawDecipherment); 
        
        // сохранить переданные параметры
        this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
        this.maskAlgorithm	= RefObject.addRef(maskAlgorithm); this.label = label;
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(rawDecipherment); RefObject.release(maskAlgorithm);
        
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); super.onClose();            
    }
    // раскодировать данные
    @Override protected byte[] decode(byte[] encoded, int bits) throws IOException
    {
        // раскодировать данные
        return Encoding.decode(hashAlgorithm, maskAlgorithm, label, encoded); 
    }
    // способ возведения в степень
    @Override protected byte[] power(
        aladdin.capi.ansi.rsa.IPrivateKey privateKey, byte[] data) throws IOException
    {
        // выполнить возведение в степень
        if (rawDecipherment == null) return super.power(privateKey, data); 
        
        // выполнить возведение в степень
        return rawDecipherment.decrypt(privateKey, data); 
    }
}
