package aladdin.capi.ansi.rsa;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkix.*;
import aladdin.asn1.iso.pkcs.pkcs1.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.capi.*; 
import java.security.spec.*;
import java.math.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры для алгоритма шифрования RSA
///////////////////////////////////////////////////////////////////////////
public class KeyFactory extends aladdin.capi.KeyFactory
{
    // конструктор
    public KeyFactory(String keyOID) { this.keyOID = keyOID; } 
    
    // идентификатор открытого ключа
    @Override public String keyOID() { return keyOID; } private final String keyOID; 
    
	// способ использования ключа
	@Override public KeyUsage getKeyUsage() 
    { 
        // указать способ использования ключа
        return new KeyUsage(
            KeyUsage.DIGITAL_SIGNATURE | KeyUsage.CERTIFICATE_SIGNATURE | 
            KeyUsage.CRL_SIGNATURE     | KeyUsage.NON_REPUDIATION       | 
            KeyUsage.DATA_ENCIPHERMENT | KeyUsage.KEY_ENCIPHERMENT
        ); 
    }
    // закодировать параметры
    @Override public IEncodable encodeParameters(aladdin.capi.IParameters parameters)
    {
        // параметры отсутствуют 
        throw new UnsupportedOperationException(); 
    }
    // раскодировать параметры
    @Override public aladdin.capi.IParameters 
        decodeParameters(IEncodable encoded) throws IOException
    {
        // параметры отсутствуют 
        throw new UnsupportedOperationException(); 
    }
	// закодировать открытый ключ
	@Override public SubjectPublicKeyInfo encodePublicKey(
        aladdin.capi.IPublicKey publicKey)
	{
        // выполнить преобразование типа
        IPublicKey rsaPublicKey = (IPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), Null.INSTANCE
		); 
		// закодировать значение ключа
		RSAPublicKey encodedKey = new RSAPublicKey(
            new Integer(rsaPublicKey.getModulus       ()), 
            new Integer(rsaPublicKey.getPublicExponent())
		); 
        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(
            algorithm, new BitString(encodedKey.encoded())
        ); 
	}
	// раскодировать открытый ключ
	@Override public aladdin.capi.IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException
	{
		// извлечь закодированный открытый ключ
		RSAPublicKey decodedKey = new RSAPublicKey(
            Encodable.decode(encoded.subjectPublicKey().value())
        ); 
        // сохранить раскодированные значения
        BigInteger modulus        = decodedKey.modulus       ().value(); 
        BigInteger publicExponent = decodedKey.publicExponent().value(); 
        
        // вернуть открытый ключ
        return new PublicKey(this, modulus, publicExponent); 
	}
	// закодировать личный ключ
	@Override public PrivateKeyInfo encodePrivateKey(
        aladdin.capi.IPrivateKey privateKey, Attributes attributes) throws IOException
	{
        // выполнить преобразование типа
        IPrivateKey rsaPrivateKey = (IPrivateKey)privateKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), Null.INSTANCE
		); 
		// закодировать личный ключ
		RSAPrivateKey encodedKey = new RSAPrivateKey(
			new Integer(0			                      ), 
            new Integer(rsaPrivateKey.getModulus		()), 
			new Integer(rsaPrivateKey.getPublicExponent ()), 
            new Integer(rsaPrivateKey.getPrivateExponent()), 
			new Integer(rsaPrivateKey.getPrimeP		    ()), 
            new Integer(rsaPrivateKey.getPrimeQ		    ()), 
			new Integer(rsaPrivateKey.getPrimeExponentP	()), 
            new Integer(rsaPrivateKey.getPrimeExponentQ	()), 
			new Integer(rsaPrivateKey.getCrtCoefficient	()), null
		); 
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), 
            algorithm, new OctetString(encodedKey.encoded()), attributes
        ); 
	}
	// раскодировать личный ключ
	@Override public aladdin.capi.IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException
	{
        // раскодировать личный ключ
        RSAPrivateKey decodedKey = new RSAPrivateKey(
            Encodable.decode(encoded.privateKey().value())
        );
        // сохранить извлеченные параметры
        BigInteger modulus		   = decodedKey.modulus        ().value();
        BigInteger publicExponent  = decodedKey.publicExponent ().value(); 
        BigInteger privateExponent = decodedKey.privateExponent().value(); 
        BigInteger prime1          = decodedKey.prime1         ().value(); 
        BigInteger prime2          = decodedKey.prime2         ().value(); 
        BigInteger exponent1       = decodedKey.exponent1      ().value(); 
        BigInteger exponent2       = decodedKey.exponent2      ().value(); 
        BigInteger coefficient     = decodedKey.coefficient    ().value(); 
        
        // вернуть личный ключ
        return new PrivateKey(factory, null, keyOID, 
            modulus, publicExponent, privateExponent, 
            prime1, prime2, exponent1, exponent2, coefficient
        ); 
	}
    // закодировать пару ключей
    @Override public final PrivateKeyInfo encodeKeyPair(
        aladdin.capi.IPrivateKey privateKey, aladdin.capi.IPublicKey publicKey, 
        Attributes attributes) throws IOException
    {
        // закодировать личный ключ
        return encodePrivateKey(privateKey, attributes); 
    }
	// раскодировать пару ключей
    @Override public KeyPair decodeKeyPair(
        Factory factory, PrivateKeyInfo encoded) throws IOException
    {
        // раскодировать личный ключ
        try (IPrivateKey privateKey = (IPrivateKey)decodePrivateKey(factory, encoded))
        {  
            // вычислить открытый ключ 
            IPublicKey publicKey = new PublicKey(this, 
                privateKey.getModulus(), privateKey.getPublicExponent()
            );
            // вернуть пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
    } 
    // создать параметры
    @Override public aladdin.capi.IParameters createParameters(
        AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException
    {
        // создать параметры
        return Parameters.getInstance(paramSpec); 
    }
    // создать открытый ключ
    @Override public aladdin.capi.IPublicKey createPublicKey(KeySpec keySpec) 
        throws InvalidKeySpecException, IOException
    {
        // в зависимости от типа данных
        if (keySpec instanceof RSAPublicKeySpec)
        {
            // выполнить преобразование типа
            RSAPublicKeySpec rsaKeySpec = (RSAPublicKeySpec)keySpec; 
            
            // создать открытый ключ
            return new PublicKey(this, 
                rsaKeySpec.getModulus(), rsaKeySpec.getPublicExponent()
            ); 
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
        IPublicKey rsaPublicKey = (IPublicKey)publicKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(RSAPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new RSAPublicKeySpec(
                rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent()
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
        if (keySpec instanceof RSAPrivateCrtKeySpec)
        {
            // выполнить преобразование типа
            RSAPrivateCrtKeySpec rsaKeySpec = (RSAPrivateCrtKeySpec)keySpec; 
            
            // создать личный ключ
            return new PrivateKey(factory, null, keyOID, 
                rsaKeySpec.getModulus(), rsaKeySpec.getPublicExponent(), 
                rsaKeySpec.getPrivateExponent(), rsaKeySpec.getPrimeP(), 
                rsaKeySpec.getPrimeQ(), rsaKeySpec.getPrimeExponentP(), 
                rsaKeySpec.getPrimeExponentQ(), rsaKeySpec.getCrtCoefficient()
            ); 
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
        IPrivateKey rsaPrivateKey = (IPrivateKey)privateKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(RSAPrivateCrtKeySpec.class))
        {
            // вернуть данные ключа
            return new RSAPrivateCrtKeySpec(rsaPrivateKey.getModulus(), 
                rsaPrivateKey.getPublicExponent(), rsaPrivateKey.getPrivateExponent(), 
                rsaPrivateKey.getPrimeP(), rsaPrivateKey.getPrimeQ(), 
                rsaPrivateKey.getPrimeExponentP(), rsaPrivateKey.getPrimeExponentQ(), 
                rsaPrivateKey.getCrtCoefficient()
            ); 
        }
        // в зависимости от типа данных
        if (specType.isAssignableFrom(RSAPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new RSAPrivateKeySpec(rsaPrivateKey.getModulus(), 
                rsaPrivateKey.getPrivateExponent()
            ); 
        }
        // вызвать базовую функцию
        return super.getPrivateKeySpec(privateKey, specType); 
    }
}
