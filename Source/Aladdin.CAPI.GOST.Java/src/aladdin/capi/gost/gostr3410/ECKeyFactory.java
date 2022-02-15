package aladdin.capi.gost.gostr3410;
import aladdin.math.*; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.gost.*; 
import aladdin.capi.*; 
import aladdin.capi.ec.*; 
import java.security.spec.*; 
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключа ГОСТ Р 34.10-2001,2012
///////////////////////////////////////////////////////////////////////////
public class ECKeyFactory extends KeyFactory 
{
    // способ кодирования чисел
    public static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 

    // конструктор
    public ECKeyFactory(String keyOID) { this.keyOID = keyOID; }

    // идентификаторы открытых ключей
    @Override public String keyOID() { return keyOID; } private final String keyOID; 
    
	// способ использования ключа
	@Override public KeyUsage getKeyUsage() 
    { 
        // указать способ использования ключа
        return new KeyUsage(
            KeyUsage.DIGITAL_SIGNATURE | KeyUsage.CERTIFICATE_SIGNATURE | 
            KeyUsage.CRL_SIGNATURE     | KeyUsage.NON_REPUDIATION       | 
            KeyUsage.KEY_ENCIPHERMENT  | KeyUsage.KEY_AGREEMENT
        );          
    }
    // закодировать параметры 
    @Override public IEncodable encodeParameters(aladdin.capi.IParameters parameters)
    {
        // преобразовать тип параметров
        INamedParameters namedParameters = (INamedParameters)parameters; 

        // извлечь идентификаторы наборов
        String paramOID = namedParameters.paramOID(); 
        String hashOID  = namedParameters.hashOID (); 
        
        // в зависимости от значения идентификатора
        if (keyOID.equals(aladdin.asn1.gost.OID.GOSTR3410_2001))
        {
            // извлечь идентификаторы наборов
            String sboxOID = namedParameters.sboxOID(); 

            // идентификатор таблицы подстановок
            ObjectIdentifier encodedSBoxOID = null; if (sboxOID != null)
            {
                // закодировать идентификатор таблицы подстановок
                encodedSBoxOID = new ObjectIdentifier(sboxOID); 
            }
            // закодировать параметры
            return new GOSTR3410PublicKeyParameters2001(new ObjectIdentifier(paramOID), 
                new ObjectIdentifier(hashOID), encodedSBoxOID
            ); 
        }
        else {
            // закодировать параметры
            return new GOSTR3410PublicKeyParameters2012(
                new ObjectIdentifier(paramOID), new ObjectIdentifier(hashOID)
            ); 
        }
    }
    // раскодировать параметры алгоритма
    @Override public IECParameters decodeParameters(IEncodable encoded) throws IOException
    {
        // в зависимости от значения идентификатора
        if (keyOID.equals(aladdin.asn1.gost.OID.GOSTR3410_2001))
        {
            // раскодировать параметры
            GOSTR3410PublicKeyParameters2001 parameters = new GOSTR3410PublicKeyParameters2001(encoded); 

            // вернуть раскодированные параметры
            return new ECNamedParameters2001(parameters); 
        }
        else {
            // раскодировать параметры
            GOSTR3410PublicKeyParameters2012 parameters = new GOSTR3410PublicKeyParameters2012(encoded); 
            
            // в зависимости от значения идентификатора
            if (keyOID.equals(aladdin.asn1.gost.OID.GOSTR3410_2012_256))
            {
                // вернуть раскодированные параметры
                return new ECNamedParameters2012(parameters, 256); 
            }
            else {
                // вернуть раскодированные параметры
                return new ECNamedParameters2012(parameters, 512); 
            }
        }
    }
	// закодировать открытый ключ
	@Override public SubjectPublicKeyInfo encodePublicKey(IPublicKey publicKey)
	{
        // выполнить преобразование типа
        IECParameters parameters = (IECParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IECPublicKey ecPublicKey = (IECPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
		// создать буфер для объединения точек
		byte[] xy = new byte[(parameters.getOrder().bitLength() + 7) / 8 * 2]; 

        // закодировать координаты точки
        Convert.fromBigInteger(ecPublicKey.getW().getAffineX(), ENDIAN, xy,             0, xy.length / 2);
        Convert.fromBigInteger(ecPublicKey.getW().getAffineY(), ENDIAN, xy, xy.length / 2, xy.length / 2);
        
		// закодировать значение открытого ключа
		byte[] encodedXY = new OctetString(xy).encoded(); 
        
		// закодировать значение ключа
		BitString encoded = new BitString(encodedXY, encodedXY.length * 8); 
        
        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(algorithm, encoded); 
    }
    // раскодировать открытый ключ
	@Override public aladdin.capi.IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException
	{
        // раскодировать параметры
        IECParameters parameters = decodeParameters(encoded.algorithm().parameters()); 
        
        // определить размер открытого ключа в байтах
        int publicSize = (parameters.getOrder().bitLength() + 7) / 8 * 2; 

		// извлечь закодированный открытый ключ алгоритма
		byte[] bitsPublicKey = encoded.subjectPublicKey().value(); 
        
        // при усеченном размере
        if (bitsPublicKey.length < publicSize + 2) { byte[] temp = new byte[publicSize + 2]; 

			// переразместить закодированный открытый ключ алгоритма
			System.arraycopy(bitsPublicKey, 0, temp, 0, bitsPublicKey.length); bitsPublicKey = temp;
		}
		// извлечь открытый ключ алгоритма
		byte[] xy = new OctetString(Encodable.decode(bitsPublicKey)).value();

		// проверить корректность размера ключа
		if (xy.length != publicSize) throw new IOException();

		// преобразовать координаты точки в большие числа
		BigInteger X = Convert.toBigInteger(xy,             0, xy.length / 2, ENDIAN); 
        BigInteger Y = Convert.toBigInteger(xy, xy.length / 2, xy.length / 2, ENDIAN);
        
        // создать точку на эллиптической кривой
        ECPoint q = new ECPoint(X, Y); 
        
        // вернуть открытый ключ
        return new ECPublicKey(this, parameters, q); 
	}
    // закодировать личный ключ
	@Override public PrivateKeyInfo encodePrivateKey(
        IPrivateKey privateKey, Attributes attributes) throws IOException
    {
        // закодировать личный ключ
        return encodePrivateKey(privateKey, null, 0, attributes); 
    }
    // закодировать личный ключ
	public PrivateKeyInfo encodePrivateKey(
        IPrivateKey privateKey, IRand rand, int k, Attributes attributes) throws IOException
    {
        // закодировать личный ключ
        return encodeKeyPair(privateKey, null, rand, k, attributes); 
    }
    // раскодировать личный ключ
	@Override public aladdin.capi.IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException
	{
        // раскодировать параметры
        IECParameters parameters = decodeParameters(
            encoded.privateKeyAlgorithm().parameters()
        ); 
		// раскодировать личный ключ
		IEncodable encodable = Encodable.decode(encoded.privateKey().value());

		// определить размер каждой маски
		BigInteger q = parameters.getOrder(); int sizeKey = (q.bitLength() + 7) / 8;  

		// в зависимости от типа данных
		if (encodable.tag().equals(Tag.SEQUENCE))
		{
			// раскодировать данные
			GOSTR3410PrivateKeyValueInfo privateKeyValueInfo = 
				new GOSTR3410PrivateKeyValueInfo(encodable); 

			// прочитать замаскированное значение ключа и маски
			encodable = privateKeyValueInfo.privateKeyMaskValue(); 
		}
		// прочитать замаскированное значение ключа и маски
		byte[] buffer = new OctetString(encodable).value(); 

		// проверить корректность данных
		if (buffer.length == 0 || (buffer.length % sizeKey) != 0)
		{
			// при ошибке выбросить исключение
			throw new IOException();
		}
		// извлечь замаскированное значение ключа
		BigInteger d = Convert.toBigInteger(buffer, 0, sizeKey, ENDIAN);

		// для всех наложений масок
		for (int i = 0; i < buffer.length / sizeKey - 1; i++)
		{
			// определить смещение маски
            int offset = sizeKey * (i + 1);   

            // раскодировать значение маски
            BigInteger mask = Convert.toBigInteger(buffer, offset, sizeKey, ENDIAN); 

			// выполнить умножение больших чисел
			d = d.multiply(mask).mod(q); 
		}
        // вернуть личный ключ
        return new ECPrivateKey(factory, null, keyOID, parameters, d); 
	}
    // закодировать пару ключей
    @Override public PrivateKeyInfo encodeKeyPair(IPrivateKey privateKey, 
        IPublicKey publicKey, Attributes attributes) throws IOException
    {
        // закодировать пару ключей
        return encodeKeyPair(privateKey, publicKey, null, 0, attributes); 
    }
    // закодировать пару ключей
    public PrivateKeyInfo encodeKeyPair(IPrivateKey privateKey, 
        IPublicKey publicKey, IRand rand, int k, Attributes attributes) throws IOException
	{
        // выполнить преобразование типа
        IECParameters parameters = (IECParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IECPrivateKey ecPrivateKey = (IECPrivateKey)privateKey; 
        IECPublicKey  ecPublicKey  = (IECPublicKey )publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
        // определить параметр Q
        BigInteger q = parameters.getOrder(); int sizeKey = (q.bitLength() + 7) / 8;

        // выделить память для замаскированного значение ключа и масок
		byte[] buffer = new byte[sizeKey * (k + 1)]; BigInteger d = ecPrivateKey.getS(); 
        
        // для всех операции наложения маски
        for (int i = 0; i < k; i++)
        {
            // определить смещение маски
            int offset = sizeKey * (i + 1); BigInteger mask;  
            do { 
                // сгенерировать значение маски
                rand.generate(buffer, offset, sizeKey);

                // раскодировать значение маски
                mask = Convert.toBigInteger(buffer, offset, sizeKey, ENDIAN).mod(q); 
            }
            while (mask.signum() == 0); 

            // выполнить умножение больших чисел
            d = d.multiply(mask.modInverse(q)).mod(q);
        }
		// скопировать личный ключ в буфер
        Convert.fromBigInteger(d, ENDIAN, buffer, 0, sizeKey); 
        
        // закодировать ключ
        IEncodable encodedKey = new OctetString(buffer); if (publicKey != null) 
        {
            // создать буфер для объединения точек
            byte[] xy = new byte[sizeKey * 2]; 

            // закодировать координаты точки
            Convert.fromBigInteger(ecPublicKey.getW().getAffineX(), ENDIAN, xy,       0, sizeKey);
            Convert.fromBigInteger(ecPublicKey.getW().getAffineY(), ENDIAN, xy, sizeKey, sizeKey);
            
            // закодировать пару ключей
            encodedKey = new GOSTR3410PrivateKeyValueInfo(
                (OctetString)encodedKey, new OctetString(xy)
            ); 
        }
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), 
            algorithm, new OctetString(encodedKey.encoded()), attributes
        ); 
	}
	// раскодировать пару ключей
    @Override public KeyPair decodeKeyPair(Factory factory,  
        PrivateKeyInfo encoded) throws IOException
    {
	    // раскодировать личный ключ
	    IEncodable encodable = Encodable.decode(encoded.privateKey().value());

        // раскодировать личный ключ
        try (IECPrivateKey privateKey = (IECPrivateKey)decodePrivateKey(factory, encoded))
        {  
            // преобразовать тип параметров
            ECParameters ecParameters = (ECParameters)privateKey.parameters(); 

	        // в зависимости от типа данных
	        if (encodable.tag().equals(Tag.SEQUENCE))
            {
		        // раскодировать данные
		        GOSTR3410PrivateKeyValueInfo privateKeyValueInfo = new GOSTR3410PrivateKeyValueInfo(encodable); 

	            // извлечь открытый ключ алгоритма
	            byte[] xy = privateKeyValueInfo.publicKeyValue().value();

	            // преобразовать координаты точки в большие числа
	            BigInteger X = Convert.toBigInteger(xy,             0, xy.length / 2, ENDIAN); 
                BigInteger Y = Convert.toBigInteger(xy, xy.length / 2, xy.length / 2, ENDIAN);

                // создать точку на эллиптической кривой
                ECPoint Q = new ECPoint(X, Y); 

                // создать объект открытого ключа 
	            IPublicKey publicKey = new ECPublicKey(this, ecParameters, Q);

                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
            else { 
                // вычислить открытый ключ
                ECPoint Q = ecParameters.getCurve().multiply(
                    ecParameters.getGenerator(), privateKey.getS()
                );
                // создать объект открытого ключа 
                IPublicKey publicKey = new ECPublicKey(this, ecParameters, Q);

                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
        }
    }
    
    // создать параметры
    @Override public aladdin.capi.IParameters createParameters(
        AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException, IOException 
    { 
        // в зависимости от типа данных
        if (paramSpec instanceof ECParameterSpec)
        {
            // выполнить преобразование типа
            if (paramSpec instanceof IParameters) return (IParameters)paramSpec; 
            
            // выполнить преобразование типа
            ECParameterSpec ecParamSpec = (ECParameterSpec)paramSpec; 
        
            // проверить корректность параметров
            if (ecParamSpec.getCofactor() != 1) throw new InvalidParameterSpecException(); 
            try { 
                // преобразовать тип кривой
                CurveFp curve = CurveFp.convert(ecParamSpec.getCurve());
        
                // создать параметры ключа
                return new ECParameters(curve, ecParamSpec.getGenerator(), ecParamSpec.getOrder()); 
            }
            // при возникновении ошибки
            catch (IllegalArgumentException e) 
            { 
                // изменить тип исключения
                throw new InvalidParameterSpecException(e.getMessage()); 
            }
        }
        // вызвать базовую функцию
        return super.createParameters(paramSpec); 
    }
    // извлечь параметры
    @Override public AlgorithmParameterSpec getParametersSpec(
        aladdin.capi.IParameters parameters, 
        Class<? extends AlgorithmParameterSpec> specType) 
    { 
        // выполнить преобразование типа
        IECParameters ecParameters = (IECParameters)parameters; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(ECParameterSpec.class))
        {
            // выполнить преобразование типа
            return ECParameters.convert(ecParameters); 
        }
        // вызвать базовую функцию
        return super.getParametersSpec(parameters, specType); 
    } 
    // создать открытый ключ
    @Override public aladdin.capi.IPublicKey createPublicKey(KeySpec keySpec) 
        throws InvalidKeySpecException, IOException
    {
        // проверить требуемый тип данных
        if (keySpec instanceof ECPublicKeySpec)
        {
            // выполнить преобразование типа
            ECPublicKeySpec ecKeySpec = (ECPublicKeySpec)keySpec; 
            
            // получить параметры 
            ECParameterSpec ecParamSpec = ecKeySpec.getParams(); 
            
            // проверить корректность параметров
            if (ecParamSpec.getCofactor() != 1) throw new InvalidKeySpecException(); 
            
            // в зависимости от типа параметров
            if (ecParamSpec instanceof IECParameters)
            {            
                // выполнить преобразование типа
                IECParameters parameters = (IECParameters)ecParamSpec; 
                
                // создать открытый ключ
                return new ECPublicKey(this, parameters, ecKeySpec.getW()); 
            }
            // в зависимости от типа параметров
            if (ecParamSpec instanceof INamedParameters)
            {            
                // выполнить преобразование типа
                INamedParameters namedParameters = (INamedParameters)ecParamSpec; 
                
                // создать параметры ключа
                IECParameters parameters = ECNamedParameters.create(
                    namedParameters.paramOID(), namedParameters.hashOID(), 
                    namedParameters.sboxOID()
                ); 
                // создать открытый ключ
                return new ECPublicKey(this, parameters, ecKeySpec.getW()); 
            }
            try { 
                // преобразовать тип кривой
                CurveFp curve = CurveFp.convert(ecParamSpec.getCurve());
        
                // создать параметры ключа
                IECParameters parameters = new ECParameters(curve, 
                    ecParamSpec.getGenerator(), ecParamSpec.getOrder()
                ); 
                // создать открытый ключ
                return new ECPublicKey(this, parameters, ecKeySpec.getW()); 
            }
            // при возникновении ошибки
            catch (IllegalArgumentException e) 
            { 
                // изменить тип исключения
                throw new InvalidKeySpecException(e.getMessage()); 
            }
        }
        // вызвать базовую функцию
        return super.createPublicKey(keySpec); 
    }
    // извлечь данные открытого ключа
    @Override public KeySpec getPublicKeySpec(
        aladdin.capi.IPublicKey publicKey, Class<? extends KeySpec> specType)
    {
        // выполнить преобразование типа
        IECParameters parameters = (IECParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IECPublicKey ecPublicKey = (IECPublicKey)publicKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(ECPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new ECPublicKeySpec(ecPublicKey.getW(), 
                ECParameters.convert(parameters)
            ); 
        }
        // вызвать базовую функцию
        return super.getPublicKeySpec(publicKey, specType); 
    }
    // создать личный ключ
    @Override public aladdin.capi.IPrivateKey createPrivateKey(
        Factory factory, KeySpec keySpec) 
        throws InvalidKeySpecException, IOException
    {
        // проверить требуемый тип данных
        if (keySpec instanceof ECPrivateKeySpec)
        {
            // выполнить преобразование типа
            ECPrivateKeySpec ecKeySpec = (ECPrivateKeySpec)keySpec; 
            
            // получить параметры 
            ECParameterSpec ecParamSpec = ecKeySpec.getParams(); 
            
            // проверить корректность параметров
            if (ecParamSpec.getCofactor() != 1) throw new InvalidKeySpecException(); 
            
            // в зависимости от типа параметров
            if (ecParamSpec instanceof IECParameters)
            {            
                // выполнить преобразование типа
                IECParameters parameters = (IECParameters)ecParamSpec; 
                
                // создать личный ключ
                return new ECPrivateKey(factory, null, keyOID, parameters, ecKeySpec.getS()); 
            }
            // в зависимости от типа параметров
            if (ecParamSpec instanceof INamedParameters)
            {            
                // выполнить преобразование типа
                INamedParameters namedParameters = (INamedParameters)ecParamSpec; 
                
                // создать параметры ключа
                IECParameters parameters = ECNamedParameters.create(
                    namedParameters.paramOID(), namedParameters.hashOID(), 
                    namedParameters.sboxOID()
                ); 
                // создать личный ключ
                return new ECPrivateKey(factory, null, keyOID, parameters, ecKeySpec.getS()); 
            }
            try { 
                // преобразовать тип кривой
                CurveFp curve = CurveFp.convert(ecParamSpec.getCurve());
        
                // создать параметры ключа
                IECParameters parameters = new ECParameters(curve, 
                    ecParamSpec.getGenerator(), ecParamSpec.getOrder()
                ); 
                // создать личный ключ
                return new ECPrivateKey(factory, null, keyOID, parameters, ecKeySpec.getS()); 
            }
            // при возникновении ошибки
            catch (IllegalArgumentException e) 
            { 
                // изменить тип исключения
                throw new InvalidKeySpecException(e.getMessage()); 
            }
        }
        // вызвать базовую функцию
        return super.createPrivateKey(factory, keySpec); 
    }
    // извлечь данные личного ключа
    @Override public KeySpec getPrivateKeySpec(
        aladdin.capi.IPrivateKey privateKey, 
        Class<? extends KeySpec> specType) throws IOException
    {
        // выполнить преобразование типа
        IECParameters parameters = (IECParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IECPrivateKey ecPrivateKey = (IECPrivateKey)privateKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(ECPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new ECPrivateKeySpec(ecPrivateKey.getS(), 
                ECParameters.convert(parameters)
            ); 
        }
        // вызвать базовую функцию
        return super.getPrivateKeySpec(privateKey, specType); 
    }
}
