package aladdin.capi.stb.sign.stb11762;
import aladdin.*; 
import aladdin.asn1.iso.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи хэш-значения СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.VerifyHash
{
    // алгоритм проверки подписи данных
    private final aladdin.capi.VerifyData verifyAlgorithm; 
        
    // конструктор
    public VerifyHash(aladdin.capi.VerifyData verifyAlgorithm)
    {
        // сохранить переданные параметры
        this.verifyAlgorithm = RefObject.addRef(verifyAlgorithm); 
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить используемые ресурсы
        RefObject.release(verifyAlgorithm); super.onClose(); 
    }
    @Override public void verify(aladdin.capi.IPublicKey publicKey, 
        AlgorithmIdentifier hashParameters, byte[] data, byte[] signature) 
        throws IOException, SignatureException
    {
        // проверить подпись данных
        verifyAlgorithm.verify(publicKey, data, 0, data.length, signature); 
    }
}
