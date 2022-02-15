package aladdin.capi.stb.sign.stb11762;
import aladdin.*; 
import aladdin.asn1.iso.*;
import aladdin.capi.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм выработки подписи хэш-значения СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class SignHash extends aladdin.capi.SignHash
{
    // алгоритм подписи данных
    private final aladdin.capi.SignData signAlgorithm; 
        
    // конструктор
    public SignHash(aladdin.capi.SignData signAlgorithm) 
    { 
        // сохранить переданные параметры
        this.signAlgorithm = RefObject.addRef(signAlgorithm); 
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить используемые ресурсы
        RefObject.release(signAlgorithm); super.onClose(); 
    }
    @Override public byte[] sign(aladdin.capi.IPrivateKey privateKey, 
        IRand rand, AlgorithmIdentifier hashParameters, byte[] data) throws IOException
    {
        while (true) 
        {
            // подписать данные
            try { return signAlgorithm.sign(privateKey, rand, data, 0, data.length); } 

            // обработать ошибку
            catch (IllegalStateException e) {} 
        }
    }
}
