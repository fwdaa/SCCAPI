using System; 

namespace Aladdin.CAPI.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // Фабрика кодирования кючей
    ////////////////////////////////////////////////////////////////////////////////
    public class KeyFactory : CAPI.KeyFactory
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // конструктор
        public KeyFactory(string keyOID) { this.keyOID = keyOID; }

        // идентификатор открытого ключа
        public override string KeyOID { get { return keyOID; }} private string keyOID;

	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            // указать способ использования ключа
            return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                   KeyUsage.CrlSignature     | KeyUsage.NonRepudiation       | 
                   KeyUsage.KeyAgreement;
        }
        // закодировать параметры
        public override ASN1.IEncodable EncodeParameters(CAPI.IParameters parameters)
        {
            // закодировать параметры
            return EncodeParameters(parameters, EC.Encoding.Uncompressed, true); 
        }
        // закодировать параметры
        public virtual ASN1.IEncodable EncodeParameters(
            CAPI.IParameters parameters, EC.Encoding encoding, bool useOID) 
        {
            // при указании идентификатора 
            if (parameters is INamedParameters && useOID)
            {
                // закодировать идентификатор параметров
                return new ASN1.ObjectIdentifier(((INamedParameters)parameters).Oid); 
            }
            // преобразовать тип параметров
            IParameters ecParameters = (IParameters)parameters; 
            
            // в зависимости от типа поля
            if (ecParameters.Curve.Field is EC.FieldF2m)
            {
                // указать фабрику кодирования
                KeyFactory keyFactory = new F2m.KeyFactory(keyOID); 

                // закодировать параметры
                return keyFactory.EncodeParameters(parameters, encoding, useOID); 
            }
            else {
                // указать фабрику кодирования
                KeyFactory keyFactory = new Fp.KeyFactory(keyOID); 

                // закодировать параметры
                return keyFactory.EncodeParameters(parameters, encoding, useOID); 
            }
        }
        // раскодировать параметры
	    public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encoded)
        {
            // раскодировать параметры
            encoded = new ASN1.ANSI.X962.ECDomainParameters().Decode(encoded); 

            // проверить указание параметров
            if (encoded is ASN1.Null) throw new NotSupportedException(); 

            // указать начальные условия
            string oid = null; ASN1.ANSI.X962.SpecifiedECDomain parameters; 
        
            // при указании идентификатора
            if (encoded is ASN1.ObjectIdentifier)
            {
                // раскодировать идентификатор параметров
                oid = ((ASN1.ObjectIdentifier)encoded).Value; 
            
                // получить набор параметров
                parameters = ASN1.ANSI.X962.SpecifiedECDomain.Parameters(oid); 
            }
            // получить набор параметров
            else parameters = (ASN1.ANSI.X962.SpecifiedECDomain)encoded;

            // определить тип поля
            string fieldOID = parameters.FieldID.FieldType.Value; 
            
            // в зависимости от типа поля
            if (fieldOID == ASN1.ANSI.OID.x962_c2_field)
            {
                // указать фабрику кодирования
                F2m.KeyFactory keyFactory = new F2m.KeyFactory(keyOID); 
                
                // раскодировать параметры
                return keyFactory.DecodeParameters(oid, parameters); 
            }
            else {
                // указать фабрику кодирования
                Fp.KeyFactory keyFactory = new Fp.KeyFactory(keyOID); 
                
                // раскодировать параметры
                return keyFactory.DecodeParameters(oid, parameters); 
            }
        }
        // закодировать открытый ключ
        public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(CAPI.IPublicKey publicKey) 
        {
            // закодировать открытый ключ
            return EncodePublicKey(publicKey, EC.Encoding.Uncompressed, true); 
        }
        // закодировать открытый ключ
        public ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(
            CAPI.IPublicKey publicKey, EC.Encoding encoding, bool useOID) 
        {
            // выполнить преобразование типа
            IParameters parameters = (IParameters)publicKey.Parameters; 

            // выполнить преобразование типа
            IPublicKey ecPublicKey = (IPublicKey)publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters, encoding, useOID)
		    ); 
		    // закодировать значение ключа
		    ASN1.BitString encoded = new ASN1.BitString(
                parameters.Curve.Encode(ecPublicKey.Q, encoding)
            ); 
            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(algorithm, encoded); 
        }
        // раскодировать открытый ключ
        public override CAPI.IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded)
        {
            // раскодировать параметры
            IParameters parameters = (IParameters)DecodeParameters(
                encoded.Algorithm.Parameters
            ); 
            // раскодировать значение открытого ключа
		    EC.Point q = parameters.Curve.Decode(encoded.SubjectPublicKey.Value); 

            // вернуть открытый ключ
            return new PublicKey(this, parameters, q); 
        }
        // закодировать личный ключ
        public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            CAPI.IPrivateKey privateKey, ASN1.ISO.Attributes attributes)
        {
            // закодировать личный ключ
            return EncodePrivateKey(privateKey, attributes, EC.Encoding.Uncompressed, true); 
        }
        // закодировать личный ключ
        public ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            CAPI.IPrivateKey privateKey, ASN1.ISO.Attributes attributes, 
            EC.Encoding encoding, bool useOID) 
        {
            // закодировать личный ключ
            return EncodeKeyPair(privateKey, null, attributes, encoding, useOID); 
        }
        // раскодировать личный ключ
        public override CAPI.IPrivateKey DecodePrivateKey(
            CAPI.Factory factory, ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
            // указать закодированные параметры
            ASN1.IEncodable encodedParameters = encoded.PrivateKeyAlgorithm.Parameters; 
        
            // раскодировать личный ключ
            ASN1.ANSI.X962.ECPrivateKey decodedKey = new ASN1.ANSI.X962.ECPrivateKey(
                ASN1.Encodable.Decode(encoded.PrivateKey.Value)
            );
            // скорректировать параметры алгоритма
            if (decodedKey.Parameters != null) encodedParameters = decodedKey.Parameters;

            // раскодировать параметры
            IParameters parameters = (IParameters)DecodeParameters(encodedParameters); 
        
            // раскодировать значение личного ключа
            Math.BigInteger d = Math.Convert.ToBigInteger(decodedKey.PrivateKey.Value, Endian); 

            // вернуть личный ключ
            return new PrivateKey(factory, null, keyOID, parameters, d); 
        }
        // закодировать пару ключей
	    public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            CAPI.IPrivateKey privateKey, CAPI.IPublicKey publicKey, ASN1.ISO.Attributes attributes)
        {
            // закодировать пару ключей
            return EncodeKeyPair(privateKey, publicKey, attributes, EC.Encoding.Uncompressed, true); 
        }
        // закодировать пару ключей
	    public ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            CAPI.IPrivateKey privateKey, CAPI.IPublicKey publicKey,
            ASN1.ISO.Attributes attributes, EC.Encoding encoding, bool useOID)
        {
            // выполнить преобразование типа
            IParameters parameters = (IParameters)privateKey.Parameters; 

            // выполнить преобразование типа
            IPrivateKey ecPrivateKey = (IPrivateKey)privateKey; 
            IPublicKey  ecPublicKey  = (IPublicKey )publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters, encoding, useOID)
		    ); 
            // закодировать большое число
            ASN1.OctetString encodedD = new ASN1.OctetString(
                Math.Convert.FromBigInteger(ecPrivateKey.D, Endian)
            ); 
		    // при наличии открытого ключа
		    ASN1.BitString encodedQ = null; if (publicKey != null)
            {
                // закодировать значение ключа
                encodedQ = new ASN1.BitString(parameters.Curve.Encode(ecPublicKey.Q, encoding)); 
            }
            // закодировать личный ключ
            ASN1.ANSI.X962.ECPrivateKey encodedKey = new ASN1.ANSI.X962.ECPrivateKey(
                new ASN1.Integer(1), encodedD, algorithm.Parameters, encodedQ
            ); 
            // вернуть закодированное представление
            return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(new ASN1.Integer(0), 
                algorithm, new ASN1.OctetString(encodedKey.Encoded), attributes
            ); 
        }
	    // раскодировать пару ключей
        public override KeyPair DecodeKeyPair(CAPI.Factory factory, 
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
            // указать закодированные параметры
            ASN1.IEncodable encodedParameters = encoded.PrivateKeyAlgorithm.Parameters; 
        
            // раскодировать личный ключ
            ASN1.ANSI.X962.ECPrivateKey decodedKey = new ASN1.ANSI.X962.ECPrivateKey(
                ASN1.Encodable.Decode(encoded.PrivateKey.Value)
            );
            // скорректировать параметры алгоритма
            if (decodedKey.Parameters != null) encodedParameters = decodedKey.Parameters;
        
            // раскодировать параметры
            IParameters parameters = (IParameters)DecodeParameters(encodedParameters); 

            // раскодировать значение личного ключа
            Math.BigInteger d = Math.Convert.ToBigInteger(decodedKey.PrivateKey.Value, Endian); 
        
            // создать объект личного ключа
            using (IPrivateKey privateKey = new PrivateKey(factory, null, keyOID, parameters, d))
            {
                // при наличии открытого ключа
                if (decodedKey.PublicKey != null)
                {
                    // раскодировать значение открытого ключа
                    EC.Point q = parameters.Curve.Decode(decodedKey.PublicKey.Value); 

                    // создать открытый ключ
                    IPublicKey publicKey = new PublicKey(this, parameters, q);

                    // вернуть пару ключей
                    return new KeyPair(publicKey, privateKey, null); 
                }
                else { 
		            // вычислить открытый ключ
                    EC.Point Q = parameters.Curve.Multiply(parameters.Generator, privateKey.D);		      

                    // создать объект открытого ключа 
                    IPublicKey publicKey = new PublicKey(this, parameters, Q);

                    // вернуть пару ключей
                    return new KeyPair(publicKey, privateKey, null); 
                }
            } 
        } 
    }
}
