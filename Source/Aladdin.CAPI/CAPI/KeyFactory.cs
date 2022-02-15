namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Фабрика кодирования ключей
    ///////////////////////////////////////////////////////////////////////////
	public abstract class KeyFactory { public abstract string KeyOID { get; } 

        // способ использования ключа
        public virtual KeyUsage GetKeyUsage() { return KeyUsage.None; } 

        // закодировать параметры 
        public abstract ASN1.IEncodable EncodeParameters(IParameters parameters);
        // раскодировать параметры 
	    public abstract IParameters DecodeParameters(ASN1.IEncodable encoded);

        // закодировать открытый ключ
	    public abstract ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(
            IPublicKey publicKey
        );
         // раскодировать открытый ключ
	    public abstract IPublicKey DecodePublicKey(
            ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded
        );
    
        // закодировать личный ключ
	    public abstract ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            IPrivateKey privateKey, ASN1.ISO.Attributes attributes
        );
	    // раскодировать закрытый ключ
	    public abstract IPrivateKey DecodePrivateKey(
            Factory factory, ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded
        ); 

        // закодировать пару ключей
	    public abstract ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            IPrivateKey privateKey, IPublicKey publicKey, ASN1.ISO.Attributes attributes
        );
	    // раскодировать пару ключей
        public abstract KeyPair DecodeKeyPair(
            Factory factory, ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded
        );  
	}
}
