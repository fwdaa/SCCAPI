namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Ассиметричный алгоритм зашифрования
    ///////////////////////////////////////////////////////////////////////////
	public abstract class Encipherment : TransportKeyWrap
	{
		// зашифровать данные 
		public abstract byte[] Encrypt(IPublicKey key, IRand rand, byte[] data);

	    // зашифровать ключ
	    public override TransportKeyData Wrap(
            ASN1.ISO.AlgorithmIdentifier algorithmParameters, 
            IPublicKey publicKey, IRand rand, ISecretKey key)
        {
            // проверить тип ключа
            if (key.Value == null) throw new InvalidKeyException(); 
        
            // зашифровать данные
            byte[] encrypted = Encrypt(publicKey, rand, key.Value); 
        
            // вернуть зашифрованные данные
            return new TransportKeyData(algorithmParameters, encrypted); 
        }
    }
}
