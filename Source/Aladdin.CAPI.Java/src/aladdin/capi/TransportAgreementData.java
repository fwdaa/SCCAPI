package aladdin.capi;

///////////////////////////////////////////////////////////////////////////////
// Данные, используемые при согласовании ключа
///////////////////////////////////////////////////////////////////////////////
public final class TransportAgreementData
{
    // конструктор
    public TransportAgreementData(IPublicKey publicKey, byte[] random, byte[][] encryptedKeys) 
    { 
        // сохранить переданные параметры
        this.publicKey = publicKey; this.random = random; this.encryptedKeys = encryptedKeys; 
    }
    // использованный открытый ключ
    public final IPublicKey publicKey; 
    // случайные данные и зашифрованные ключи
    public final byte[] random; public final byte[][] encryptedKeys;
}
