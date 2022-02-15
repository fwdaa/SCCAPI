using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Параметры для алгоритма шифрования RSA
	///////////////////////////////////////////////////////////////////////////
	public class KeyFactory : CAPI.KeyFactory
	{
        // конструктор
        public KeyFactory(string keyOID) { this.keyOID = keyOID; } 

        // идентификаторы открытых ключей
        public override string KeyOID { get { return keyOID; }} private string keyOID; 

	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            // указать способ использования ключа
            return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                   KeyUsage.CrlSignature     | KeyUsage.NonRepudiation       | 
                   KeyUsage.DataEncipherment | KeyUsage.KeyEncipherment; 
        }
        // закодировать параметры 
        public override ASN1.IEncodable EncodeParameters(CAPI.IParameters parameters)
        {
            // операция не поддерживается
            throw new NotSupportedException(); 
        }
        // раскодировать параметры
	    public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encodable)
        {
            // параметры отсутствуют
            throw new NotSupportedException(); 
        }
		// закодировать открытый ключ
		public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(CAPI.IPublicKey publicKey)
		{
            // выполнить преобразование типа
            IPublicKey rsaPublicKey = (IPublicKey)publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
		    ); 
		    // закодировать значение ключа
		    ASN1.ISO.PKCS.PKCS1.RSAPublicKey encodedKey = new ASN1.ISO.PKCS.PKCS1.RSAPublicKey(
                new ASN1.Integer(rsaPublicKey.Modulus       ), 
                new ASN1.Integer(rsaPublicKey.PublicExponent)
		    ); 
            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(
                algorithm, new ASN1.BitString(encodedKey.Encoded)
            ); 
		}
		// раскодировать открытый ключ
		public override CAPI.IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded)
		{
		    // извлечь закодированный открытый ключ
		    ASN1.ISO.PKCS.PKCS1.RSAPublicKey decodedKey = new ASN1.ISO.PKCS.PKCS1.RSAPublicKey(
                ASN1.Encodable.Decode(encoded.SubjectPublicKey.Value)
            ); 
            // сохранить раскодированные значения
            Math.BigInteger modulus        = decodedKey.Modulus       .Value; 
            Math.BigInteger publicExponent = decodedKey.PublicExponent.Value; 
        
            // вернуть открытый ключ
            return new PublicKey(this, modulus, publicExponent); 
		}
		// закодировать личный ключ
		public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            CAPI.IPrivateKey privateKey, ASN1.ISO.Attributes attributes)
		{
            // выполнить преобразование типа
            IPrivateKey rsaPrivateKey = (IPrivateKey)privateKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
		    ); 
		    // закодировать личный ключ
		    ASN1.ISO.PKCS.PKCS1.RSAPrivateKey encodedKey = new ASN1.ISO.PKCS.PKCS1.RSAPrivateKey(
			    new ASN1.Integer(0			                  ), 
                new ASN1.Integer(rsaPrivateKey.Modulus		  ), 
			    new ASN1.Integer(rsaPrivateKey.PublicExponent ), 
                new ASN1.Integer(rsaPrivateKey.PrivateExponent), 
			    new ASN1.Integer(rsaPrivateKey.PrimeP		  ), 
                new ASN1.Integer(rsaPrivateKey.PrimeQ		  ), 
			    new ASN1.Integer(rsaPrivateKey.PrimeExponentP ), 
                new ASN1.Integer(rsaPrivateKey.PrimeExponentQ ), 
			    new ASN1.Integer(rsaPrivateKey.CrtCoefficient ), null
		    ); 
            // вернуть закодированное представление
            return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(
                new ASN1.Integer(0), algorithm, 
                new ASN1.OctetString(encodedKey.Encoded), attributes
            ); 
		}
		// раскодировать личный ключ
		public override CAPI.IPrivateKey DecodePrivateKey(
            CAPI.Factory factory, ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded)
		{
            // раскодировать личный ключ
            ASN1.ISO.PKCS.PKCS1.RSAPrivateKey decodedKey = new ASN1.ISO.PKCS.PKCS1.RSAPrivateKey(
                ASN1.Encodable.Decode(encoded.PrivateKey.Value)
            );
            // сохранить извлеченные параметры
            Math.BigInteger modulus		    = decodedKey.Modulus        .Value;
            Math.BigInteger publicExponent  = decodedKey.PublicExponent .Value; 
            Math.BigInteger privateExponent = decodedKey.PrivateExponent.Value; 
            Math.BigInteger prime1          = decodedKey.Prime1         .Value; 
            Math.BigInteger prime2          = decodedKey.Prime2         .Value; 
            Math.BigInteger exponent1       = decodedKey.Exponent1      .Value; 
            Math.BigInteger exponent2       = decodedKey.Exponent2      .Value; 
            Math.BigInteger coefficient     = decodedKey.Coefficient    .Value; 
        
            // вернуть личный ключ
            return new PrivateKey(factory, null, keyOID, 
                modulus, publicExponent, privateExponent, 
                prime1, prime2, exponent1, exponent2, coefficient
            ); 
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
                // вычислить открытый ключ 
                IPublicKey publicKey = new PublicKey(
                    this, privateKey.Modulus, privateKey.PublicExponent
                );
                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
        } 
	}
}
