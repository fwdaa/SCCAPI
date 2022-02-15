using System; 
using System.IO; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключа ГОСТ Р 34.10-2001,2012
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.GOSTR3410
{
    public class ECKeyFactory : KeyFactory 
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // конструктор
        public ECKeyFactory(String keyOID) { this.keyOID = keyOID; }

        // идентификаторы открытых ключей
        public override string KeyOID { get { return keyOID; }} private string keyOID; 
    
	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            // указать способ использования ключа
            return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                   KeyUsage.CrlSignature     | KeyUsage.NonRepudiation       | 
                   KeyUsage.KeyEncipherment  | KeyUsage.KeyAgreement;
        }
        // закодировать параметры
	    public override ASN1.IEncodable EncodeParameters(CAPI.IParameters parameters)
	    {
            // преобразовать тип параметров
            INamedParameters namedParameters = (INamedParameters)parameters; 
        
            // извлечь идентификаторы наборов
            string paramOID = namedParameters.ParamOID; 
            string hashOID  = namedParameters.HashOID ; 

            // в зависимости от значения идентификатора
            if (keyOID == ASN1.GOST.OID.gostR3410_2001)
            {
                // извлечь идентификаторы наборов
                string sboxOID  = namedParameters.SBoxOID ; 
        
                // идентификатор таблицы подстановок
                ASN1.ObjectIdentifier encodedSBoxOID = null; if (sboxOID != null)
                {
                    // закодировать идентификатор таблицы подстановок
                    encodedSBoxOID = new ASN1.ObjectIdentifier(sboxOID); 
                }
	            // закодировать параметры
	            return new ASN1.GOST.GOSTR3410PublicKeyParameters2001(
                    new ASN1.ObjectIdentifier(paramOID), 
                    new ASN1.ObjectIdentifier(hashOID ), encodedSBoxOID
                ); 
            }
            else { 
	            // закодировать параметры
	            return new ASN1.GOST.GOSTR3410PublicKeyParameters2012(
                    new ASN1.ObjectIdentifier(paramOID), 
                    new ASN1.ObjectIdentifier(hashOID )
                ); 
            }
	    }
        // раскодировать параметры
        public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encoded) 
        {
            // в зависимости от значения идентификатора
            if (keyOID == ASN1.GOST.OID.gostR3410_2001)
            {
	            // раскодировать параметры
	            ASN1.GOST.GOSTR3410PublicKeyParameters2001 parameters =
                    new ASN1.GOST.GOSTR3410PublicKeyParameters2001(encoded); 
        
                // вернуть раскодированные параметры
                return new ECNamedParameters2001(parameters); 
            }
            else { 
	            // раскодировать параметры
	            ASN1.GOST.GOSTR3410PublicKeyParameters2012 parameters =
                    new ASN1.GOST.GOSTR3410PublicKeyParameters2012(encoded); 

                // в зависимости от значения идентификатора
                if (keyOID == ASN1.GOST.OID.gostR3410_2012_256)
                {
                    // вернуть раскодированные параметры
                    return new ECNamedParameters2012(parameters, 256); 
                }
                // вернуть раскодированные параметры
                else return new ECNamedParameters2012(parameters, 512); 
            }
        }
	    // закодировать открытый ключ
	    public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(CAPI.IPublicKey publicKey)
	    {
            // выполнить преобразование типа
            IECParameters parameters = (IECParameters)publicKey.Parameters; 

            // выполнить преобразование типа
            IECPublicKey ecPublicKey = (IECPublicKey)publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
		    // создать буфер для объединения точек
		    byte[] xy = new byte[(parameters.Order.BitLength + 7) / 8 * 2]; 

            // закодировать координаты точки
            Math.Convert.FromBigInteger(ecPublicKey.Q.X, Endian, xy,             0, xy.Length / 2);
            Math.Convert.FromBigInteger(ecPublicKey.Q.Y, Endian, xy, xy.Length / 2, xy.Length / 2);
        
	        // закодировать значение открытого ключа
		    byte[] encodedXY = new ASN1.OctetString(xy).Encoded; 

		    // закодировать значение ключа
		    ASN1.BitString encoded = new ASN1.BitString(encodedXY, encodedXY.Length * 8); 
        
            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(algorithm, encoded); 
	    }
        // раскодировать открытый ключ
	    public override CAPI.IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded)
	    {
            // раскодировать параметры
            IECParameters parameters = (IECParameters)DecodeParameters(
                encoded.Algorithm.Parameters
            ); 
            // определить размер открытого ключа в байтах
            int publicSize = (parameters.Order.BitLength + 7) / 8 * 2; 

		    // извлечь закодированный открытый ключ алгоритма
		    byte[] bitsPublicKey = encoded.SubjectPublicKey.Value; 
            
            // при усеченном размере
            if (bitsPublicKey.Length < publicSize + 2) { byte[] temp = new byte[publicSize + 2]; 

			    // переразместить закодированный открытый ключ алгоритма
			    Array.Copy(bitsPublicKey, 0, temp, 0, bitsPublicKey.Length); bitsPublicKey = temp;
		    }
		    // извлечь открытый ключ алгоритма
		    byte[] xy = new ASN1.OctetString(ASN1.Encodable.Decode(bitsPublicKey)).Value;

		    // проверить корректность размера ключа
		    if (xy.Length != publicSize) throw new InvalidDataException();

		    // преобразовать координаты точки в большие числа
		    Math.BigInteger X = Math.Convert.ToBigInteger(xy,             0, xy.Length / 2, Endian); 
            Math.BigInteger Y = Math.Convert.ToBigInteger(xy, xy.Length / 2, xy.Length / 2, Endian);

            // создать точку на эллиптической кривой
            EC.Point q = new EC.Point(X, Y); 

            // вернуть открытый ключ
            return new ECPublicKey(this, parameters, q); 
	    }
        // закодировать личный ключ
	    public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            CAPI.IPrivateKey privateKey, ASN1.ISO.Attributes attributes)
        {
            // закодировать личный ключ
            return EncodePrivateKey(privateKey, null, 0, attributes); 
        }
        // закодировать личный ключ
	    public ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            CAPI.IPrivateKey privateKey, IRand rand, int k, ASN1.ISO.Attributes attributes)
        {
            // закодировать личный ключ
            return EncodeKeyPair(privateKey, null, rand, k, attributes); 
        }
        // раскодировать личный ключ
	    public override CAPI.IPrivateKey DecodePrivateKey(
            CAPI.Factory factory, ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded)
	    {
            // раскодировать параметры
            IECParameters parameters = (IECParameters)DecodeParameters(
                encoded.PrivateKeyAlgorithm.Parameters
            ); 
		    // раскодировать личный ключ
            ASN1.IEncodable encodable = ASN1.Encodable.Decode(encoded.PrivateKey.Value);

		    // определить размер каждой маски
		    Math.BigInteger q = parameters.Order; int sizeKey = (q.BitLength + 7) / 8;  

		    // в зависимости от типа данных
		    if (encodable.Tag.Equals(ASN1.Tag.Sequence))
		    {
			    // раскодировать данные
			    ASN1.GOST.GOSTR3410PrivateKeyValueInfo privateKeyValueInfo =
                    new ASN1.GOST.GOSTR3410PrivateKeyValueInfo(encodable); 

			    // прочитать замаскированное значение ключа и маски
			    encodable = privateKeyValueInfo.PrivateKeyMaskValue; 
		    }
		    // прочитать замаскированное значение ключа и маски
		    byte[] buffer = new ASN1.OctetString(encodable).Value; 

		    // проверить корректность данных
		    if (buffer.Length == 0 || (buffer.Length % sizeKey) != 0)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidDataException();
		    }
		    // извлечь замаскированное значение ключа
		    Math.BigInteger d = Math.Convert.ToBigInteger(buffer, 0, sizeKey, Endian);

		    // для всех наложений масок
		    for (int i = 0; i < buffer.Length / sizeKey - 1; i++)
		    {
			    // определить смещение маски
                int offset = sizeKey * (i + 1);   

                // раскодировать значение маски
                Math.BigInteger mask = Math.Convert.ToBigInteger(
                    buffer, offset, sizeKey, Endian
                ); 
			    // выполнить умножение больших чисел
			    d = (d * mask) % q; 
		    } 
            // вернуть личный ключ
            return new ECPrivateKey(factory, null, keyOID, parameters, d); 
	    }
        // закодировать пару ключей
	    public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            CAPI.IPrivateKey privateKey, CAPI.IPublicKey publicKey, ASN1.ISO.Attributes attributes)
        {
            // закодировать пару ключей
            return EncodeKeyPair(privateKey, publicKey, null, 0, attributes); 
        }
        // закодировать пару ключей
	    public ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            CAPI.IPrivateKey privateKey, CAPI.IPublicKey publicKey, 
            IRand rand, int k, ASN1.ISO.Attributes attributes)
	    {
            // выполнить преобразование типа
            IECParameters parameters = (IECParameters)privateKey.Parameters; 

            // выполнить преобразование типа
            IECPrivateKey ecPrivateKey = (IECPrivateKey)privateKey; 
            IECPublicKey  ecPublicKey  = (IECPublicKey )publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
            // определить параметр Q
            Math.BigInteger q = parameters.Order; int sizeKey = (q.BitLength + 7) / 8;

            // выделить память для замаскированного значение ключа и масок
		    byte[] buffer = new byte[sizeKey * (k + 1)]; Math.BigInteger d = ecPrivateKey.D; 

	        // для всех операции наложения маски
	        for (int i = 0; i < k; i++)
	        {
		        // определить смещение маски
                int offset = sizeKey * (i + 1); Math.BigInteger mask = null;  
                do { 
                    // сгенерировать значение маски
                    rand.Generate(buffer, offset, sizeKey);
            
                    // раскодировать значение маски
                    mask = Math.Convert.ToBigInteger(buffer, offset, sizeKey, Endian) % q; 
                }
                while (mask.Signum == 0); 
            
		        // выполнить умножение больших чисел
		        d = (d * mask.ModInverse(q)) % q;
	        }
		    // скопировать личный ключ в буфер
            Math.Convert.FromBigInteger(d, Endian, buffer, 0, sizeKey); 

            // закодировать ключ
            ASN1.IEncodable encodedKey = new ASN1.OctetString(buffer); if (publicKey != null) 
            {
                // создать буфер для объединения точек
                byte[] xy = new byte[sizeKey * 2]; 

                // закодировать координаты точки
                Math.Convert.FromBigInteger(ecPublicKey.Q.X, Endian, xy,       0, sizeKey);
                Math.Convert.FromBigInteger(ecPublicKey.Q.Y, Endian, xy, sizeKey, sizeKey);
            
                // закодировать пару ключей
                encodedKey = new ASN1.GOST.GOSTR3410PrivateKeyValueInfo(
                    (ASN1.OctetString)encodedKey, new ASN1.OctetString(xy)
                ); 
            }
            // вернуть закодированное представление
            return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(new ASN1.Integer(0), 
                algorithm, new ASN1.OctetString(encodedKey.Encoded), attributes
            ); 
	    }
	    // раскодировать пару ключей
        public override KeyPair DecodeKeyPair(CAPI.Factory factory, 
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
		    // раскодировать личный ключ
		    ASN1.IEncodable encodable = ASN1.Encodable.Decode(encoded.PrivateKey.Value);

            // раскодировать личный ключ
            using (IECPrivateKey privateKey = (IECPrivateKey)DecodePrivateKey(factory, encoded))
            {  
                // преобразовать тип параметров
                IECParameters ecParameters = (IECParameters)privateKey.Parameters; 

		        // в зависимости от типа данных
		        if (encodable.Tag == ASN1.Tag.Sequence)
                {
			        // раскодировать данные
			        ASN1.GOST.GOSTR3410PrivateKeyValueInfo privateKeyValueInfo = 
				        new ASN1.GOST.GOSTR3410PrivateKeyValueInfo(encodable); 

		            // извлечь открытый ключ алгоритма
		            byte[] xy = privateKeyValueInfo.PublicKeyValue.Value;

		            // преобразовать координаты точки в большие числа
		            Math.BigInteger X = Math.Convert.ToBigInteger(xy,             0, xy.Length / 2, Endian); 
                    Math.BigInteger Y = Math.Convert.ToBigInteger(xy, xy.Length / 2, xy.Length / 2, Endian);

                    // создать точку на эллиптической кривой
                    EC.Point Q = new EC.Point(X, Y); 

                    // создать объект открытого ключа 
		            IPublicKey publicKey = new ECPublicKey(this, ecParameters, Q);

                    // вернуть пару ключей
                    return new KeyPair(publicKey, privateKey, null); 
                }
                else { 
                    // вычислить открытый ключ
                    EC.Point Q = ecParameters.Curve.Multiply(ecParameters.Generator, privateKey.D);

                    // создать объект открытого ключа 
                    IPublicKey publicKey = new ECPublicKey(this, ecParameters, Q);

                    // вернуть пару ключей
                    return new KeyPair(publicKey, privateKey, null); 
                }
            }
        } 
    }
}