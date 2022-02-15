package aladdin.capi;
import aladdin.asn1.iso.*; 

///////////////////////////////////////////////////////////////////////////////
// Данные, используемые при передаче ключа
///////////////////////////////////////////////////////////////////////////////
public class TransportKeyData 
{
    // конструктор
    public TransportKeyData(AlgorithmIdentifier algorithm, byte[] encryptedKey) 
    { 
        // сохранить переданные параметры
        this.algorithm = algorithm; this.encryptedKey = encryptedKey; 
    }
    // использованные параметры и зашифрованный ключ
    public final AlgorithmIdentifier algorithm; public final byte[] encryptedKey; 
}
