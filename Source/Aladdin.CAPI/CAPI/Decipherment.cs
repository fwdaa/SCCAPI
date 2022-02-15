namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Ассиметричный алгоритм расшифрования
    ///////////////////////////////////////////////////////////////////////////
	public abstract class Decipherment : TransportKeyUnwrap
	{
		// расшифровать данные
		public abstract byte[] Decrypt(IPrivateKey key, byte[] data);

	    // расшифровать ключ
	    public override ISecretKey Unwrap(IPrivateKey privateKey, 
            TransportKeyData data, SecretKeyFactory keyFactory)
        {
            // расшифровать ключ
            byte[] value = Decrypt(privateKey, data.EncryptedKey); 
        
            // вернуть расшифрованный ключ
            return keyFactory.Create(value); 
        }
	}
}
