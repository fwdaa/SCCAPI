package aladdin.capi.ansi.x942;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.ansi.x942.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.capi.*; 
import java.security.spec.*; 
import javax.crypto.spec.*; 
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры для алгоритма DH
///////////////////////////////////////////////////////////////////////////
public class KeyFactory extends aladdin.capi.KeyFactory
{
    // конструктор
    public KeyFactory(String keyOID) { this.keyOID = keyOID; } 
    
    // идентификаторы открытых ключей
    @Override public String keyOID() { return keyOID; } private final String keyOID; 
    
	// способ использования ключа
	@Override public KeyUsage getKeyUsage() 
    { 
        // указать способ использования ключа
        return new KeyUsage(KeyUsage.KEY_AGREEMENT);
    }
    // закодировать параметры
	@Override public final IEncodable encodeParameters(
        aladdin.capi.IParameters parameters)
	{
        // выполнить преобразование типа
        IParameters dhParameters = (IParameters)parameters; 
        
        // извлечь параметры
        Integer p = new Integer(dhParameters.getP()); 
        Integer q = new Integer(dhParameters.getQ()); 
        Integer g = new Integer(dhParameters.getG()); 
        
		// закодировать параметры
		return new DomainParameters(p, g, q, null, null); 
	}
    // раскодировать параметры
	@Override public final IParameters decodeParameters(
        IEncodable encoded) throws IOException
	{
		// раскодировать параметры
		DomainParameters parameters = new DomainParameters(encoded); 

        // извлечь параметры
		BigInteger p = parameters.p().value(); 
        BigInteger q = parameters.q().value(); 
        BigInteger g = parameters.g().value(); 
        
        // вернуть параметры
        return new Parameters(p, q, g); 
	}
	// закодировать открытый ключ
	@Override public final SubjectPublicKeyInfo encodePublicKey(
        aladdin.capi.IPublicKey publicKey)
	{
        // выполнить преобразование типа
        IParameters parameters = (IParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IPublicKey dhPublicKey = (IPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
		// закодировать значение ключа
		BitString encoded = new BitString(new Integer(dhPublicKey.getY()).encoded()); 
        
        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(algorithm, encoded); 
	}
	// раскодировать открытый ключ
	@Override public final aladdin.capi.IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException
	{
        // раскодировать параметры
        IParameters parameters = decodeParameters(encoded.algorithm().parameters()); 
        
        // раскодировать значение открытого ключа
		BigInteger y = new Integer(Encodable.decode(encoded.subjectPublicKey().value())).value(); 
        
        // вернуть открытый ключ
        return new PublicKey(this, parameters, y); 
	}
    // закодировать личный ключ
	@Override public final PrivateKeyInfo encodePrivateKey(
        aladdin.capi.IPrivateKey privateKey, Attributes attributes) throws IOException
	{
        // выполнить преобразование типа
        IParameters parameters = (IParameters)privateKey.parameters();
        
        // выполнить преобразование типа
        IPrivateKey dhPrivateKey = (IPrivateKey)privateKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
		// закодировать значение ключа
		OctetString encoded = new OctetString(new Integer(dhPrivateKey.getX()).encoded()); 
        
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), algorithm, encoded, attributes); 
	}
    // раскодировать личный ключ
	@Override public final aladdin.capi.IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException
	{
        // раскодировать параметры
        IParameters parameters = decodeParameters(
            encoded.privateKeyAlgorithm().parameters()
        ); 
        // раскодировать значение личного ключа
        BigInteger x = new Integer(Encodable.decode(encoded.privateKey().value())).value();
        
        // вернуть личный ключ
        return new PrivateKey(factory, null, keyOID, parameters, x); 
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
            // преобразовать тип параметров
            IParameters dhParameters = (IParameters)privateKey.parameters(); 

	        // вычислить открытый ключ
	        BigInteger Y = dhParameters.getG().modPow(privateKey.getX(), dhParameters.getP());
            
            // создать объект открытого ключа 
            IPublicKey publicKey = new PublicKey(this, dhParameters, Y);

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
    // извлечь данные открытого ключа
    @Override public KeySpec getPublicKeySpec(
        aladdin.capi.IPublicKey publicKey, Class<? extends KeySpec> specType)
        throws InvalidKeySpecException
    {
        // выполнить преобразование типа
        IParameters parameters = (IParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IPublicKey dhPublicKey = (IPublicKey)publicKey; 
        
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
    // извлечь данные личного ключа
    @Override public KeySpec getPrivateKeySpec(
        aladdin.capi.IPrivateKey privateKey, Class<? extends KeySpec> specType) 
        throws InvalidKeySpecException, IOException
    {
        // выполнить преобразование типа
        IParameters parameters = (IParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IPrivateKey dhPrivateKey = (IPrivateKey)privateKey; 
        
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
