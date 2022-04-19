package aladdin.capi.ansi.x957;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.ansi.x957.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.capi.*; 
import java.security.spec.*; 
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры для алгоритма DSA
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
        return new KeyUsage(KeyUsage.DIGITAL_SIGNATURE | 
            KeyUsage.CERTIFICATE_SIGNATURE | 
            KeyUsage.CRL_SIGNATURE | KeyUsage.NON_REPUDIATION
        );
    }
    // закодировать параметры
	@Override public final IEncodable encodeParameters(
        aladdin.capi.IParameters parameters)
	{
        // выполнить преобразование типа
        IParameters dsaParameters = (IParameters)parameters; 
        
        // извлечь параметры
        Integer p = new Integer(dsaParameters.getP()); 
        Integer q = new Integer(dsaParameters.getQ()); 
        Integer g = new Integer(dsaParameters.getG()); 
        
		// закодировать параметры
		return new DssParms(p, q, g); 
	}
    // раскодировать параметры
	@Override public final IParameters decodeParameters(
        IEncodable encoded) throws IOException
	{
		// раскодировать параметры
		DssParms parameters = new DssParms(encoded); 

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
        IPublicKey dsaPublicKey = (IPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
		// закодировать значение ключа
		BitString encoded = new BitString(new Integer(dsaPublicKey.getY()).encoded()); 
        
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
        IPrivateKey dsaPrivateKey = (IPrivateKey)privateKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
		// закодировать значение ключа
		OctetString encoded = new OctetString(new Integer(dsaPrivateKey.getX()).encoded()); 
        
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
            IParameters dsaParameters = (IParameters)privateKey.parameters(); 

            // вычислить открытый ключ
		    BigInteger Y = dsaParameters.getG().modPow(privateKey.getX(), dsaParameters.getP());
            
            // создать объект открытого ключа 
            IPublicKey publicKey = new PublicKey(this, dsaParameters, Y);

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
        if (keySpec instanceof DSAPublicKeySpec)
        {
            // выполнить преобразование типа
            DSAPublicKeySpec dsaKeySpec = (DSAPublicKeySpec)keySpec; 
            
            // создать параметры ключа
            Parameters parameters = new Parameters(
                dsaKeySpec.getP(), dsaKeySpec.getQ(), dsaKeySpec.getG()
            ); 
            // создать открытый ключ
            return new PublicKey(this, parameters, dsaKeySpec.getY()); 
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
        IParameters parameters = (IParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IPublicKey dsaPublicKey = (IPublicKey)publicKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DSAPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new DSAPublicKeySpec(dsaPublicKey.getY(), 
                parameters.getP(), parameters.getQ(), parameters.getG()
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
            Parameters parameters = new Parameters(
                dsaKeySpec.getP(), dsaKeySpec.getQ(), dsaKeySpec.getG()
            ); 
            // создать личный ключ
            return new PrivateKey(factory, null, keyOID, parameters, dsaKeySpec.getX()); 
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
        IParameters parameters = (IParameters)privateKey.parameters();
        
        // выполнить преобразование типа
        IPrivateKey dsaPrivateKey = (IPrivateKey)privateKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DSAPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new DSAPrivateKeySpec(dsaPrivateKey.getX(), 
                parameters.getP(), parameters.getQ(), parameters.getG()
            ); 
        }
        // вызвать базовую функцию
        return super.getPrivateKeySpec(privateKey, specType); 
    }
}
