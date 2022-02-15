package aladdin.capi.ansi.sign.rsa.pkcs1;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.*;
import aladdin.capi.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA PKCS1.5
///////////////////////////////////////////////////////////////////////////
public class SignHash extends aladdin.capi.ansi.sign.rsa.SignHash
{
    // способ возведения в степень
    private final aladdin.capi.Decipherment rawDecipherment; 
    
    // конструктор
    public SignHash() { this(null); }
            
    // конструктор
    public SignHash(aladdin.capi.Decipherment rawDecipherment)
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
    // закодировать данные
    @Override protected byte[] encode(IRand rand, 
        AlgorithmIdentifier hashAlgorithm, byte[] hash, int bits) throws IOException
    {
        // закодировать хэш-значение 
        DigestInfo digestInfo = new DigestInfo(hashAlgorithm, new OctetString(hash)); 

        // закодировать данные
        return Encoding.encode(digestInfo.encoded(), (bits + 7) / 8); 
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
