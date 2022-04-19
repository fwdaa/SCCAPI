package aladdin.capi.gost.gostr3410;
import aladdin.math.*; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.gost.*; 
import aladdin.capi.*; 
import java.security.spec.*;
import javax.crypto.spec.*;
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключа ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////////
public class DHKeyFactory extends KeyFactory 
{
    // способ кодирования чисел
    public static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // конструктор
    public DHKeyFactory(String keyOID) { this.keyOID = keyOID; }

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
	@Override public final IEncodable encodeParameters(aladdin.capi.IParameters parameters)
	{
        // преобразовать тип параметров
        INamedParameters namedParameters = (INamedParameters)parameters; 
        
        // извлечь идентификаторы наборов
        String paramOID = namedParameters.paramOID(); 
        String hashOID  = namedParameters.hashOID (); 
        String sboxOID  = namedParameters.sboxOID (); 
        
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
    // раскодировать параметры
    @Override public final IDHParameters decodeParameters(IEncodable encoded) throws IOException
    {
	    // раскодировать параметры
	    GOSTR3410PublicKeyParameters2001 parameters = new GOSTR3410PublicKeyParameters2001(encoded); 
        
        // вернуть раскодированные параметры
        return new DHNamedParameters(parameters); 
    }
	// закодировать открытый ключ
	@Override public SubjectPublicKeyInfo encodePublicKey(IPublicKey publicKey)
	{
        // выполнить преобразование типа
        IDHParameters parameters = (IDHParameters)publicKey.parameters();
        
        // выполнить преобразование типа
        IDHPublicKey dhPublicKey = (IDHPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
		// создать буфер для объединения точек
		byte[] bufferY = new byte[(parameters.getP().bitLength() + 7) / 8]; 

        // закодировать значение открытого ключа
        Convert.fromBigInteger(dhPublicKey.getY(), ENDIAN, bufferY, 0, bufferY.length);
        
		// закодировать значение открытого ключа
		byte[] encodedY = new OctetString(bufferY).encoded(); 

		// закодировать значение ключа
		BitString encoded = new BitString(encodedY, encodedY.length * 8); 
        
        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(algorithm, encoded); 
	}
    // раскодировать открытый ключ
	@Override public aladdin.capi.IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException
	{
        // раскодировать параметры
        IDHParameters parameters = decodeParameters(encoded.algorithm().parameters()); 
        
        // определить размер открытого ключа в байтах
        int publicSize = (parameters.getP().bitLength() + 7) / 8; 
        
		// извлечь закодированный открытый ключ алгоритма
		byte[] bitsPublicKey = encoded.subjectPublicKey().value(); 
        
        // при усеченном размере
        if (bitsPublicKey.length < publicSize + 2) { byte[] temp = new byte[publicSize + 2];
		
			// переразместить закодированный открытый ключ алгоритма
			System.arraycopy(bitsPublicKey, 0, temp, 0, bitsPublicKey.length); bitsPublicKey = temp;
		}
		// извлечь открытый ключ алгоритма
		byte[] bufferY = new OctetString(Encodable.decode(bitsPublicKey)).value();

		// проверить корректность размера ключа
		if (bufferY.length != publicSize) throw new IOException(); 

        // раскодировать значение открытого ключа
        BigInteger y = Convert.toBigInteger(bufferY, 0, bufferY.length, ENDIAN);
        
        // вернуть открытый ключ
        return new DHPublicKey(this, parameters, y); 
	}
    // закодировать открытый ключ
	@Override public PrivateKeyInfo encodePrivateKey(
        IPrivateKey privateKey, Attributes attributes) throws IOException
    {
        // закодировать открытый ключ
        return encodePrivateKey(privateKey, null, 0, attributes); 
    }
    // закодировать открытый ключ
	public PrivateKeyInfo encodePrivateKey(
        IPrivateKey privateKey, IRand rand, int k, Attributes attributes) throws IOException
    {
        // закодировать открытый ключ
        return encodeKeyPair(privateKey, null, rand, k, attributes); 
    }
    // раскодировать открытый ключ
	@Override public aladdin.capi.IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException
	{
        // раскодировать параметры
        IDHParameters parameters = decodeParameters(
            encoded.privateKeyAlgorithm().parameters()
        ); 
		// раскодировать личный ключ
		IEncodable encodable = Encodable.decode(encoded.privateKey().value());

		// определить размер каждой маски
		BigInteger q = parameters.getQ(); int sizeKey = (q.bitLength() + 7) / 8;  

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
		BigInteger x = Convert.toBigInteger(buffer, 0, sizeKey, ENDIAN);

		// для всех наложений масок
		for (int i = 0; i < buffer.length / sizeKey - 1; i++)
		{
			// определить смещение маски
            int offset = sizeKey * (i + 1);   

            // раскодировать значение маски
            BigInteger mask = Convert.toBigInteger(buffer, offset, sizeKey, ENDIAN); 

			// выполнить умножение больших чисел
			x = x.multiply(mask).mod(q); 
		} 
        // вернуть личный ключ
        return new DHPrivateKey(factory, null, keyOID, parameters, x); 
	}
    // закодировать пару ключей
	@Override public PrivateKeyInfo encodeKeyPair(
        IPrivateKey privateKey, IPublicKey publicKey, 
        Attributes attributes) throws IOException
    {
        // закодировать пару ключей
        return encodeKeyPair(privateKey, publicKey, null, 0, attributes); 
    }
    // закодировать пару ключей
	public PrivateKeyInfo encodeKeyPair(IPrivateKey privateKey, 
        IPublicKey publicKey, IRand rand, int k, Attributes attributes) throws IOException
	{
        // выполнить преобразование типа
        IDHParameters parameters = (IDHParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IDHPrivateKey dhPrivateKey = (IDHPrivateKey)privateKey; 
        IDHPublicKey  dhPublicKey  = (IDHPublicKey )publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
        // определить параметр Q
        BigInteger q = parameters.getQ(); int sizeKey = (q.bitLength() + 7) / 8; 

        // выделить память для замаскированного значение ключа и масок
		byte[] buffer = new byte[sizeKey * (k + 1)]; BigInteger x =  dhPrivateKey.getX(); 
        
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
            x = x.multiply(mask.modInverse(q)).mod(q);
        }
		// скопировать личный ключ в буфер
        Convert.fromBigInteger(x, ENDIAN, buffer, 0, sizeKey); 
            
        // закодировать ключ
        IEncodable encodedKey = new OctetString(buffer); if (publicKey != null) 
        {
            // создать буфер для объединения точек
            byte[] bufferY = new byte[(parameters.getP().bitLength() + 7) / 8]; 

            // закодировать значение открытого ключа
            Convert.fromBigInteger(dhPublicKey.getY(), ENDIAN, bufferY, 0, bufferY.length);
            
            // закодировать пару ключей
            encodedKey = new GOSTR3410PrivateKeyValueInfo(
                (OctetString)encodedKey, new OctetString(bufferY)
            ); 
        }
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), 
            algorithm, new OctetString(encodedKey.encoded()), attributes
        ); 
	}
	// раскодировать пару ключей
    @Override public KeyPair decodeKeyPair(
        Factory factory, PrivateKeyInfo encoded) throws IOException
    {
        // раскодировать личный ключ
		IEncodable encodable = Encodable.decode(encoded.privateKey().value());

        // раскодировать личный ключ
        try (IDHPrivateKey privateKey = (IDHPrivateKey)decodePrivateKey(factory, encoded))
        {  
            // преобразовать тип параметров
            IDHParameters dhParameters = (IDHParameters)privateKey.parameters(); 

		    // в зависимости от типа данных
		    if (encodable.tag().equals(Tag.SEQUENCE))
            {
                // раскодировать данные
			    GOSTR3410PrivateKeyValueInfo privateKeyValueInfo = new GOSTR3410PrivateKeyValueInfo(encodable); 

		        // извлечь открытый ключ алгоритма
		        byte[] y = privateKeyValueInfo.publicKeyValue().value();

		        // преобразовать координаты точки в большие числа
                BigInteger Y = Convert.toBigInteger(y, 0, y.length, ENDIAN);
        
                // создать объект открытого ключа 
		        IPublicKey publicKey = new DHPublicKey(this, dhParameters, Y);

                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
            else { 
                // вычислить открытый ключ
                BigInteger Y = dhParameters.getG().modPow(privateKey.getX(), dhParameters.getP());
		      
                // создать объект открытого ключа 
                IPublicKey publicKey = new DHPublicKey(this, dhParameters, Y);

                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
        }
    }
    // создать параметры
    @Override public aladdin.capi.IParameters createParameters(
        AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException
    {
        // создать параметры
        return DHParameters.getInstance(paramSpec); 
    }
    // создать открытый ключ
    @Override public aladdin.capi.IPublicKey createPublicKey(KeySpec keySpec) 
        throws InvalidKeySpecException, IOException
    {
        // в зависимости от типа данных
        if (keySpec instanceof DSAPublicKeySpec)
        {
            // выполнить преобразование типа
            DSAPublicKeySpec dsaKeySpec = (DSAPublicKeySpec)keySpec; 
            
            // создать параметры ключа
            DHParameters parameters = new DHParameters(
                dsaKeySpec.getP(), dsaKeySpec.getQ(), dsaKeySpec.getG(), null
            ); 
            // создать открытый ключ
            return new DHPublicKey(this, parameters, dsaKeySpec.getY()); 
        }
        // вызвать базовую функцию
        return super.createPublicKey(keySpec); 
    }
    // извлечь данные открытого ключа
    @Override public KeySpec getPublicKeySpec(
        aladdin.capi.IPublicKey publicKey, Class<? extends KeySpec> specType)
        throws InvalidKeySpecException
    {
        // выполнить преобразование типа
        IDHParameters parameters = (IDHParameters)publicKey.parameters();
        
        // выполнить преобразование типа
        IDHPublicKey dhPublicKey = (IDHPublicKey)publicKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DSAPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new DSAPublicKeySpec(dhPublicKey.getY(), 
                parameters.getP(), parameters.getQ(), parameters.getG()
            ); 
        }
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DHPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new DHPublicKeySpec(dhPublicKey.getY(), 
                parameters.getP(), parameters.getG()
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
        // в зависимости от типа данных
        if (keySpec instanceof DSAPrivateKeySpec)
        {
            // выполнить преобразование типа
            DSAPrivateKeySpec dsaKeySpec = (DSAPrivateKeySpec)keySpec; 
            
            // создать параметры ключа
            DHParameters parameters = new DHParameters(
                dsaKeySpec.getP(), dsaKeySpec.getQ(), dsaKeySpec.getG(), null
            ); 
            // создать личный ключ
            return new DHPrivateKey(factory, null, keyOID, parameters, dsaKeySpec.getX()); 
        }
        // вызвать базовую функцию
        return super.createPrivateKey(factory, keySpec); 
    }
    // извлечь данные личного ключа
    @Override public KeySpec getPrivateKeySpec(
        aladdin.capi.IPrivateKey privateKey, Class<? extends KeySpec> specType) 
        throws InvalidKeySpecException, IOException
    {
        // выполнить преобразование типа
        IDHParameters parameters = (IDHParameters)privateKey.parameters();
        
        // выполнить преобразование типа
        IDHPrivateKey dhPrivateKey = (IDHPrivateKey)privateKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DSAPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new DSAPrivateKeySpec(dhPrivateKey.getX(), 
                parameters.getP(), parameters.getQ(), parameters.getG()
            ); 
        }
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DHPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new DHPrivateKeySpec(dhPrivateKey.getX(), 
                parameters.getP(), parameters.getG()
            ); 
        }
        // вызвать базовую функцию
        return super.getPrivateKeySpec(privateKey, specType); 
    }
}
