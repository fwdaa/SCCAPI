package aladdin.capi.ansi.keyx.rsa.pkcs1;
import aladdin.*; 
import aladdin.capi.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм зашифрования RSA PKCS1
///////////////////////////////////////////////////////////////////////////
public class Encipherment extends aladdin.capi.ansi.keyx.rsa.Encipherment
{
    // способ возведения в степень
    private final aladdin.capi.Encipherment rawEncipherment; 
    
    // конструктор
    public Encipherment() { this(null); }
            
    // конструктор
    public Encipherment(aladdin.capi.Encipherment rawEncipherment)
    {
        // сохранить переданные параметры
        this.rawEncipherment = RefObject.addRef(rawEncipherment); 
    }
    // деструктор
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(rawEncipherment); super.onClose();
    }
    // закодировать данные
    @Override protected byte[] encode(IRand rand, byte[] data, int bits) throws IOException
    {
        // закодировать данные
        return Encoding.encode(rand, data, (bits + 7) / 8); 
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
