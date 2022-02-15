namespace Aladdin.CAPI.ANSI.X957
{
	///////////////////////////////////////////////////////////////////////////
	// Параметры для алгоритма DSA
	///////////////////////////////////////////////////////////////////////////
	public class KeyFactory : CAPI.KeyFactory
	{
        // конструктор
        public KeyFactory(string keyOID) { this.keyOID = keyOID; } 
    
        // идентификатор открытого ключа
        public override string KeyOID { get { return keyOID; }} private string keyOID; 

	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                   KeyUsage.CrlSignature     | KeyUsage.NonRepudiation;
        }
        // закодировать параметры
	    public override ASN1.IEncodable EncodeParameters(CAPI.IParameters parameters)
	    {
            // выполнить преобразование типа
            IParameters dsaParameters = (IParameters)parameters; 

            // извлечь параметры
            ASN1.Integer p = new ASN1.Integer(dsaParameters.P); 
            ASN1.Integer q = new ASN1.Integer(dsaParameters.Q); 
            ASN1.Integer g = new ASN1.Integer(dsaParameters.G); 
        
		    // закодировать параметры
		    return new ASN1.ANSI.X957.DssParms(p, q, g); 
	    }
        // раскодировать параметры
	    public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encodable)
	    {
		    // раскодировать параметры
		    ASN1.ANSI.X957.DssParms parameters = 
                new ASN1.ANSI.X957.DssParms(encodable); 

            // извлечь параметры
		    Math.BigInteger p = parameters.P.Value; 
            Math.BigInteger q = parameters.Q.Value; 
            Math.BigInteger g = parameters.G.Value; 
        
            // вернуть параметры
            return new Parameters(p, q, g); 
	    }
		// закодировать открыйтый ключ
		public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(CAPI.IPublicKey publicKey)
		{
            // выполнить преобразование типа
            IParameters parameters = (IParameters)publicKey.Parameters; 

            // выполнить преобразование типа
            IPublicKey dsaPublicKey = (IPublicKey)publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
		    // закодировать значение ключа
		    ASN1.BitString encoded = new ASN1.BitString(new ASN1.Integer(dsaPublicKey.Y).Encoded); 
        
            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(algorithm, encoded); 
		}
		// раскодировать открыйтый ключ
		public override CAPI.IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded)
		{
            // раскодировать параметры
            IParameters parameters = (IParameters)DecodeParameters(encoded.Algorithm.Parameters); 
        
            // раскодировать значение открытого ключа
		    Math.BigInteger y = new ASN1.Integer(ASN1.Encodable.Decode(encoded.SubjectPublicKey.Value)).Value; 
        
            // вернуть открытый ключ
            return new PublicKey(this, parameters, y); 
		}
        // закодировать личный ключ
		public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            CAPI.IPrivateKey privateKey, ASN1.ISO.Attributes attributes)
		{
            // выполнить преобразование типа
            IParameters parameters = (IParameters)privateKey.Parameters; 

            // выполнить преобразование типа
            IPrivateKey dsaPrivateKey = (IPrivateKey)privateKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
		    // закодировать значение ключа
		    ASN1.OctetString encoded = new ASN1.OctetString(new ASN1.Integer(dsaPrivateKey.X).Encoded); 
        
            // вернуть закодированное представление
            return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(
                new ASN1.Integer(0), algorithm, encoded, attributes
            ); 
		}
        // раскодировать личный ключ
        public override CAPI.IPrivateKey DecodePrivateKey(
            CAPI.Factory factory, ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded)
		{
            // раскодировать параметры
            IParameters parameters = (IParameters)DecodeParameters(
                encoded.PrivateKeyAlgorithm.Parameters
            ); 
            // раскодировать значение личного ключа
            Math.BigInteger x = new ASN1.Integer(ASN1.Encodable.Decode(encoded.PrivateKey.Value)).Value;
        
            // вернуть личный ключ
            return new PrivateKey(factory, null, keyOID, parameters, x); 
		}
        // закодировать пару ключей
        public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            CAPI.IPrivateKey privateKey, CAPI.IPublicKey publicKey, 
            ASN1.ISO.Attributes attributes)
        {
            // закодировать личный ключ
            return EncodePrivateKey(privateKey, attributes); 
        }
	    // раскодировать пару ключей
        public override KeyPair DecodeKeyPair(CAPI.Factory factory, 
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
            // раскодировать личный ключ
            using (IPrivateKey privateKey = (IPrivateKey)DecodePrivateKey(factory, encoded))
            {  
                // преобразовать тип параметров
                IParameters dsaParameters = (IParameters)privateKey.Parameters; 

		        // вычислить открытый ключ
		        Math.BigInteger Y = dsaParameters.G.ModPow(privateKey.X, dsaParameters.P);

                // создать объект открытого ключа 
                IPublicKey publicKey = new PublicKey(this, dsaParameters, Y);

                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
        } 
	}
}
