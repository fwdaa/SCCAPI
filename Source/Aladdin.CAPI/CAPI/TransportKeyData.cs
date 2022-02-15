namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
    // Данные, используемые при передаче ключа
	///////////////////////////////////////////////////////////////////////////
    public class TransportKeyData 
    {
        // конструктор
        public TransportKeyData(ASN1.ISO.AlgorithmIdentifier algorithm, byte[] encryptedKey) 
        { 
            // сохранить переданные параметры
            Algorithm = algorithm; EncryptedKey = encryptedKey; 
        }
        // параметры алгоритма и зашифрованный ключ
        public readonly ASN1.ISO.AlgorithmIdentifier Algorithm; public readonly byte[] EncryptedKey; 
    }
}
