using System;
using System.IO;

namespace Aladdin.CAPI.GOST.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры ключа ГОСТ Р 34.10-1994
    ///////////////////////////////////////////////////////////////////////////
    public class DHKeyFactory : KeyFactory 
    {
        // способ кодирования чисел
        public const Math.Endian Endian = Math.Endian.LittleEndian; 

        // конструктор
        public DHKeyFactory(String keyOID) { this.keyOID = keyOID; }

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
            String paramOID = namedParameters.ParamOID; 
            String hashOID  = namedParameters.HashOID ; 
            String sboxOID  = namedParameters.SBoxOID ; 
        
            // идентификатор таблицы подстановок
            ASN1.ObjectIdentifier encodedSBoxOID = null; if (sboxOID != null)
            {
                // закодировать идентификатор таблицы подстановок
                encodedSBoxOID = new ASN1.ObjectIdentifier(sboxOID); 
            }
	        // закодировать параметры
	        return new ASN1.GOST.GOSTR3410PublicKeyParameters2001(new ASN1.ObjectIdentifier(paramOID), 
                new ASN1.ObjectIdentifier(hashOID), encodedSBoxOID
            ); 
	    }
        // раскодировать параметры
        public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encoded) 
        {
	        // раскодировать параметры
	        ASN1.GOST.GOSTR3410PublicKeyParameters2001 parameters = new ASN1.GOST.GOSTR3410PublicKeyParameters2001(encoded); 
        
            // вернуть раскодированные параметры
            return new DHNamedParameters(parameters); 
        }
	    // закодировать открытый ключ
	    public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(CAPI.IPublicKey publicKey)
	    {
            // выполнить преобразование типа
            IDHParameters parameters = (IDHParameters)publicKey.Parameters;
 
            // выполнить преобразование типа
            IDHPublicKey dhPublicKey = (IDHPublicKey)publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
		    // создать буфер для объединения точек
		    byte[] bufferY = new byte[(parameters.P.BitLength + 7) / 8]; 

            // закодировать значение открытого ключа
            Math.Convert.FromBigInteger(dhPublicKey.Y, Endian, bufferY, 0, bufferY.Length);
        
	        // закодировать значение открытого ключа
		    byte[] encodedY = new ASN1.OctetString(bufferY).Encoded; 

		    // закодировать значение ключа
		    ASN1.BitString encoded = new ASN1.BitString(encodedY, encodedY.Length * 8); 
        
            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(algorithm, encoded); 
	    }
        // раскодировать открытый ключ
	    public override CAPI.IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded) 
	    {
            // раскодировать параметры
            IDHParameters parameters = (IDHParameters)DecodeParameters(
                encoded.Algorithm.Parameters
            ); 
            // определить размер открытого ключа в байтах
            int publicSize = (parameters.P.BitLength + 7) / 8; 
        
		    // извлечь закодированный открытый ключ алгоритма
		    byte[] bitsPublicKey = encoded.SubjectPublicKey.Value; 
            
            // при усеченном размере
            if (bitsPublicKey.Length < publicSize + 2) { byte[] temp = new byte[publicSize + 2]; 

			    // переразместить закодированный открытый ключ алгоритма
			    Array.Copy(bitsPublicKey, 0, temp, 0, bitsPublicKey.Length); bitsPublicKey = temp;
		    }
		    // извлечь открытый ключ алгоритма
		    byte[] bufferY = new ASN1.OctetString(ASN1.Encodable.Decode(bitsPublicKey)).Value;

		    // проверить корректность размера ключа
		    if (bufferY.Length != publicSize) throw new InvalidDataException(); 

		    // раскодировать значение открытого ключа
            Math.BigInteger y = Math.Convert.ToBigInteger(bufferY, 0, bufferY.Length, Endian);
        
            // вернуть открытый ключ
            return new DHPublicKey(this, parameters, y); 
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
            IDHParameters parameters = (IDHParameters)DecodeParameters(
                encoded.PrivateKeyAlgorithm.Parameters
            ); 
		    // раскодировать личный ключ
		    ASN1.IEncodable encodable = ASN1.Encodable.Decode(encoded.PrivateKey.Value);

		    // определить размер каждой маски
		    Math.BigInteger q = parameters.Q; int sizeKey = (q.BitLength + 7) / 8;  

		    // в зависимости от типа данных
		    if (encodable.Tag == ASN1.Tag.Sequence)
		    {
			    // раскодировать данные
			    ASN1.GOST.GOSTR3410PrivateKeyValueInfo privateKeyValueInfo = 
				    new ASN1.GOST.GOSTR3410PrivateKeyValueInfo(encodable); 

			    // прочитать замаскированное значение ключа и маски
			    encodable = ASN1.Encodable.Decode(
                    privateKeyValueInfo.PrivateKeyMaskValue.Value); 
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
		    Math.BigInteger x = Math.Convert.ToBigInteger(buffer, 0, sizeKey, Endian);

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
			    x = x.Multiply(mask).Mod(q); 
		    } 
            // вернуть личный ключ
            return new DHPrivateKey(factory, null, keyOID, parameters, x); 
	    }
        // закодировать пару ключей
	    public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            IPrivateKey privateKey, IPublicKey publicKey, ASN1.ISO.Attributes attributes)
        {
            // закодировать пару ключей
            return EncodeKeyPair(privateKey, publicKey, null, 0, attributes); 
        }
        // закодировать пару ключей
	    public ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            IPrivateKey privateKey, IPublicKey publicKey, 
            IRand rand, int k, ASN1.ISO.Attributes attributes)
	    {
            // выполнить преобразование типа
            IDHParameters parameters = (IDHParameters)privateKey.Parameters; 

            // выполнить преобразование типа
            IDHPrivateKey dhPrivateKey = (IDHPrivateKey)privateKey; 
            IDHPublicKey  dhPublicKey  = (IDHPublicKey )publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
            // определить параметр Q
            Math.BigInteger q = parameters.Q; int sizeKey = (q.BitLength + 7) / 8; 

            // выделить память для замаскированного значение ключа и масок
		    byte[] buffer = new byte[sizeKey * (k + 1)]; Math.BigInteger x = dhPrivateKey.X;  

            // для всех операции наложения маски
            for (int i = 0; i < k; i++)
            {
	            // определить смещение маски
                int offset = sizeKey * (i + 1); Math.BigInteger mask;  
                do { 
                    // сгенерировать значение маски
                    rand.Generate(buffer, offset, sizeKey);
            
                    // раскодировать значение маски
                    mask = Math.Convert.ToBigInteger(buffer, offset, sizeKey, Endian).Mod(q); 
                }
                while (mask.Signum == 0); 
            
	            // выполнить умножение больших чисел
	            x = x.Multiply(mask.ModInverse(q)).Mod(q);
            }
		    // скопировать личный ключ в буфер
            Math.Convert.FromBigInteger(x, Endian, buffer, 0, sizeKey); 

            // закодировать ключ
            ASN1.IEncodable encodedKey = new ASN1.OctetString(buffer); if (publicKey != null) 
            {
                // создать буфер для объединения точек
                byte[] bufferY = new byte[(parameters.P.BitLength + 7) / 8]; 

                // закодировать значение открытого ключа
                Math.Convert.FromBigInteger(dhPublicKey.Y, Endian, bufferY, 0, bufferY.Length);
            
                // закодировать пару ключей
                encodedKey = new ASN1.GOST.GOSTR3410PrivateKeyValueInfo(
                    (ASN1.OctetString)encodedKey, new ASN1.OctetString(bufferY)
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
            using (IDHPrivateKey privateKey = (IDHPrivateKey)DecodePrivateKey(factory, encoded))
            {  
                // преобразовать тип параметров
                IDHParameters dhParameters = (IDHParameters)privateKey.Parameters; 

		        // в зависимости от типа данных
		        if (encodable.Tag == ASN1.Tag.Sequence)
                {
			        // раскодировать данные
			        ASN1.GOST.GOSTR3410PrivateKeyValueInfo privateKeyValueInfo = 
				        new ASN1.GOST.GOSTR3410PrivateKeyValueInfo(encodable); 

		            // извлечь открытый ключ алгоритма
		            byte[] y = privateKeyValueInfo.PublicKeyValue.Value;

		            // преобразовать координаты точки в большие числа
                    Math.BigInteger Y = Math.Convert.ToBigInteger(y, 0, y.Length, Endian);
        
                    // создать объект открытого ключа 
		            IPublicKey publicKey = new DHPublicKey(this, dhParameters, Y);

                    // вернуть пару ключей
                    return new KeyPair(publicKey, privateKey, null); 
                }
                else { 
                    // вычислить открытый ключ
                    Math.BigInteger Y = dhParameters.G.ModPow(privateKey.X, dhParameters.P);
		      
                    // создать объект открытого ключа 
                    IPublicKey publicKey = new DHPublicKey(this, dhParameters, Y);

                    // вернуть пару ключей
                    return new KeyPair(publicKey, privateKey, null); 
                }
            }
        } 
    }
}
