package aladdin.capi.ansi.sign.rsa.pkcs1;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.*;
import java.security.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи RSA PKCS1.5
///////////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.ansi.sign.rsa.VerifyHash
{
    // способ возведения в степень
    private final aladdin.capi.Encipherment rawEncipherment; 
    
    // конструктор
    public VerifyHash() { this(null); }
            
    // конструктор
    public VerifyHash(aladdin.capi.Encipherment rawEncipherment)
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
    // проверить подпись
    @Override protected void check(byte[] encoded, int bits, 
        AlgorithmIdentifier hashAlgorithm, byte[] hash) throws IOException, SignatureException
    {
        // закодировать хэш-значение 
        DigestInfo digestInfo = new DigestInfo(hashAlgorithm, new OctetString(hash)); 

        // закодировать хэш-значение 
        byte[] check = Encoding.encode(digestInfo.encoded(), encoded.length); 
        
        // проверить совпадение значений
        if (!Arrays.equals(check, encoded)) throw new SignatureException();  
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
