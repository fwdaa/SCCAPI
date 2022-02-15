package aladdin.capi.ansi.keyx.rsa.pkcs1;
import aladdin.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм расшифрования RSA PKCS1
///////////////////////////////////////////////////////////////////////////
public class Decipherment extends aladdin.capi.ansi.keyx.rsa.Decipherment
{
    // способ возведения в степень
    private final aladdin.capi.Decipherment rawDecipherment; 
    
    // конструктор
    public Decipherment() { this(null); }
            
    // конструктор
    public Decipherment(aladdin.capi.Decipherment rawDecipherment)
    {
        // сохранить переданные параметры
        this.rawDecipherment = RefObject.addRef(rawDecipherment); 
    }
    // деструктор
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(rawDecipherment); super.onClose();
    }
    // раскодировать данные
    @Override protected byte[] decode(byte[] encoded, int bits) throws IOException
    {
        // раскодировать данные
        return Encoding.decode(encoded); 
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
