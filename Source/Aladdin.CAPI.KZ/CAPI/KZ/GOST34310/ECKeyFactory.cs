using System; 

namespace Aladdin.CAPI.KZ.GOST34310
{ 
    ///////////////////////////////////////////////////////////////////////////
    // Параметры ключа ГОСТ Р 34.10-2001
    ///////////////////////////////////////////////////////////////////////////
    public class ECKeyFactory : KeyFactory
    {
        // идентификатор ключа и параметры ключа
        private string keyOID; private ECNamedParameters parameters; 

        // конструктор
        public ECKeyFactory(string keyOID) { this.keyOID = keyOID; 

            // в зависимости от идентификатора ключа
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a) 
            {
                // указать параметры ключа
                parameters = new ECNamedParameters(keyOID, ASN1.GOST.OID.ecc_signs_A); 
            }
            // в зависимости от идентификатора ключа
            else if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b) 
            {
                // указать параметры ключа
                parameters = new ECNamedParameters(keyOID, ASN1.GOST.OID.ecc_signs_B); 
            }
            // в зависимости от идентификатора ключа
            else if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_c) 
            {
                // указать параметры ключа
                parameters = new ECNamedParameters(keyOID, ASN1.GOST.OID.ecc_signs_C); 
            }
            // в зависимости от идентификатора ключа
            else if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a_xch) 
            {
                // указать параметры ключа
                parameters = new ECNamedParameters(keyOID, ASN1.GOST.OID.ecc_exchanges_A); 
            }
            // в зависимости от идентификатора ключа
            else if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b_xch) 
            {
                // указать параметры ключа
                parameters = new ECNamedParameters(keyOID, ASN1.GOST.OID.ecc_exchanges_B); 
            }
            // при ошибке выбросить исключение
            else throw new NotSupportedException(); 
        } 
    
        // идентификаторы открытых ключей
        public override string KeyOID { get { return keyOID; }}

	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            // для специальных ключей
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b_xch)
            {
                // указать способ использования ключа
                return KeyUsage.KeyAgreement; 
            }
            // для специальных ключей
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b_xch)
            {
                // указать способ использования ключа
                return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                       KeyUsage.CrlSignature     | KeyUsage.NonRepudiation       | 
                       KeyUsage.KeyAgreement; 
            }
            else { 
                // указать способ использования ключа
                return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                       KeyUsage.CrlSignature     | KeyUsage.NonRepudiation;       
            }
        }
        // закодировать параметры
        public override ASN1.IEncodable EncodeParameters(
            CAPI.IParameters parameters) { return ASN1.Null.Instance; }
        // раскодировать параметры
        public override CAPI.IParameters 
            DecodeParameters(ASN1.IEncodable encoded) { return parameters; }

	    // закодировать открытый ключ
	    public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(IPublicKey publicKey)
        {
		    // преобразовать тип ключа
		    GOST.GOSTR3410.IECPublicKey ecPublicKey = 
			    (GOST.GOSTR3410.IECPublicKey)publicKey; 

		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
		    ); 
		    // выделить буфер требуемого размера
            byte[] blob = new byte[80]; byte[] header = new byte[] {
                0x06, 0x02, 0x00, 0x00, // PUBLICKEYBLOB
                0x00, 0x00, 0x00, 0x00, // AlgID
                0x00, 0x45, 0x43, 0x31, // EC1
                0x00, 0x02, 0x00, 0x00, // 512 бит
            }; 
            // указать идентификатор ключа
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a    ) { header[4] = 0x3A; header[5] = 0xAA; } else 
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b    ) { header[4] = 0x40; header[5] = 0xAA; } else 
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_c    ) { header[4] = 0x41; header[5] = 0xAA; } else 
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a_xch) { header[4] = 0x45; header[5] = 0xA0; } else 
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b_xch) { header[4] = 0x46; header[5] = 0xA0; } else 

            // при ошибке выбросить исключение
            throw new NotSupportedException(); Array.Copy(header, 0, blob, 0, header.Length); 
            
		    // закодировать координаты точки
		    Math.Convert.FromBigInteger(ecPublicKey.Q.X, Math.Endian.LittleEndian, blob, 16, 32); 
		    Math.Convert.FromBigInteger(ecPublicKey.Q.Y, Math.Endian.LittleEndian, blob, 48, 32); 

            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(algorithm, new ASN1.BitString(blob)); 
        }
        // раскодировать открытый ключ
	    public override IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded)
        {
            // выделить буфер для координат точек
            byte[] x = new byte[32]; byte[] y = new byte[32]; 

		    // скопировать координаты точки
		    Array.Copy(encoded.SubjectPublicKey.Value, 16, x, 0, x.Length); 
		    Array.Copy(encoded.SubjectPublicKey.Value, 48, y, 0, y.Length); 

		    // раскодировать координаты точки
		    Math.BigInteger X = Math.Convert.ToBigInteger(x, Math.Endian.LittleEndian); 
		    Math.BigInteger Y = Math.Convert.ToBigInteger(y, Math.Endian.LittleEndian); 

		    // создать точку эллиптической кривой
		    EC.Point q = new EC.Point(X, Y); 

		    // создать открытый ключ
		    return new GOST.GOSTR3410.ECPublicKey(this, parameters, q); 
        }
        // закодировать личный ключ
	    public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            IPrivateKey privateKey, ASN1.ISO.Attributes attributes)
        {
		    // преобразовать тип ключа
		    GOST.GOSTR3410.IECPrivateKey ecPrivateKey = 
			    (GOST.GOSTR3410.IECPrivateKey)privateKey; 

		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
            ); 
		    // закодировать значение личного ключа
		    byte[] d = Math.Convert.FromBigInteger(ecPrivateKey.D, Math.Endian.BigEndian, 32); 

            // закодировать личный ключ
            ASN1.KZ.ECPrivateKey encodedKey = new ASN1.KZ.ECPrivateKey(
                new ASN1.Integer(1), new ASN1.OctetString(d)
            ); 
            // вернуть закодированное представление
            return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(new ASN1.Integer(0), 
                algorithm, new ASN1.OctetString(encodedKey.Encoded), attributes
            ); 
        }
	    // раскодировать личный ключ
	    public override IPrivateKey DecodePrivateKey(CAPI.Factory factory, 
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded)
        {
            // раскодировать личный ключ
            ASN1.KZ.ECPrivateKey encodedKey = new ASN1.KZ.ECPrivateKey(
                ASN1.Encodable.Decode(encoded.Content)
            ); 
		    // раскодировать значение личного ключа
            Math.BigInteger D = Math.Convert.ToBigInteger(encodedKey.Value.Value, Math.Endian.BigEndian); 

		    // создать личный ключ
		    return new GOST.GOSTR3410.ECPrivateKey(factory, null, KeyOID, parameters, D); 
        }
        // закодировать пару ключей
	    public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            CAPI.IPrivateKey privateKey, CAPI.IPublicKey publicKey, ASN1.ISO.Attributes attributes)
        {
            // закодировать личный ключ
            return EncodePrivateKey(privateKey, attributes); 
        }
	    // раскодировать пару ключей
        public override KeyPair DecodeKeyPair(CAPI.Factory factory, 
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
            // раскодировать личный ключ
            using (GOST.GOSTR3410.IECPrivateKey privateKey = 
                (GOST.GOSTR3410.IECPrivateKey)DecodePrivateKey(factory, encoded))
            {  
                // преобразовать тип параметров
                GOST.GOSTR3410.IECParameters ecParameters = 
                    (GOST.GOSTR3410.IECParameters)privateKey.Parameters; 

		        // вычислить открытый ключ
		        EC.Point Q = ecParameters.Curve.Multiply(ecParameters.Generator, privateKey.D); 

                // создать объект открытого ключа 
                IPublicKey publicKey = new GOST.GOSTR3410.ECPublicKey(this, ecParameters, Q);

                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
        } 
    }
}
