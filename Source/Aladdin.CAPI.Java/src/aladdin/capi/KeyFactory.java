package aladdin.capi;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика кодирования ключей
///////////////////////////////////////////////////////////////////////////
public abstract class KeyFactory 
{ 
    // идентификатор ключа
    public abstract String keyOID(); 

	// способ использования ключа
	public KeyUsage getKeyUsage() { return KeyUsage.NONE; } 
    
    // закодировать параметры
    public abstract IEncodable encodeParameters(IParameters parameters); 
    // раскодировать параметры
    public abstract IParameters decodeParameters(IEncodable encoded) throws IOException; 
    
    // закодировать открытый ключ
	public abstract SubjectPublicKeyInfo encodePublicKey(IPublicKey publicKey);
     // раскодировать открытый ключ
	public abstract IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException;
    
    // закодировать личный ключ
	public abstract PrivateKeyInfo encodePrivateKey(
        IPrivateKey privateKey, Attributes attributes) throws IOException;
	// раскодировать закрытый ключ
	public abstract IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException; 

    // закодировать пару ключей
	public abstract PrivateKeyInfo encodeKeyPair(
        IPrivateKey privateKey, IPublicKey publicKey, 
        Attributes attributes) throws IOException;
	// раскодировать пару ключей
    public abstract KeyPair decodeKeyPair(
        Factory factory, PrivateKeyInfo encoded) throws IOException;  

    // создать параметры
    public IParameters createParameters(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException, IOException { return null; }
    // извлечь параметры
    public AlgorithmParameterSpec getParametersSpec(
        IParameters parameters, Class<? extends AlgorithmParameterSpec> specType) { return null; } 
    
    // создать открытый ключ
    public IPublicKey createPublicKey(KeySpec keySpec) 
        throws InvalidKeySpecException, IOException
    {
        // проверить тип данных
        if (!(keySpec instanceof EncodedKeySpec)) return null; 
        
        // выполнить преобразование типа
        EncodedKeySpec encodedKeySpec = (EncodedKeySpec)keySpec; 
            
        // проверить формат данных
        if (!encodedKeySpec.getFormat().equals("X.509")) return null; 
        
        // раскодировать данные
        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(
            Encodable.decode(encodedKeySpec.getEncoded())
        ); 
        // извлечь идентификатор открытого ключа
        String keyOID = publicKeyInfo.algorithm().algorithm().value(); 
        
        // проверить совпадение идентификатора
        if (!keyOID.equals(keyOID())) throw new UnsupportedOperationException(); 
            
        // раскодировать открытый ключ
        return decodePublicKey(publicKeyInfo); 
    }
    // извлечь данные открытого ключа
    public KeySpec getPublicKeySpec(
        IPublicKey publicKey, Class<? extends KeySpec> specType)
    {
        // получить закодированное представление
        byte[] encoded = publicKey.getEncoded(); if (encoded == null)
        {
            // проверить наличие представления
            throw new UnsupportedOperationException();
        }
        // проверить требуемый формат
        if (specType.isAssignableFrom(X509EncodedKeySpec.class))
        {
            // вернуть закодированное представление
            return new X509EncodedKeySpec(encoded); 
        }
        return null; 
    }
    // создать личный ключ
    public IPrivateKey createPrivateKey(Factory factory, KeySpec keySpec) 
        throws InvalidKeySpecException, IOException
    {
        // проверить тип данных
        if (!(keySpec instanceof EncodedKeySpec)) return null; 
        
        // выполнить преобразование типа
        EncodedKeySpec encodedKeySpec = (EncodedKeySpec)keySpec; 
            
        // проверить формат данных
        if (!encodedKeySpec.getFormat().equals("PKCS#8")) return null; 
        
        // раскодировать данные
        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
            Encodable.decode(encodedKeySpec.getEncoded())
        ); 
        // извлечь идентификатор открытого ключа
        String keyOID = privateKeyInfo.privateKeyAlgorithm().algorithm().value(); 
            
        // проверить совпадение идентификатора
        if (!keyOID.equals(keyOID())) throw new UnsupportedOperationException(); 
        
        // раскодировать личный ключ
        return decodePrivateKey(factory, privateKeyInfo); 
    }
    // извлечь данные личного ключа
    public KeySpec getPrivateKeySpec(
        IPrivateKey privateKey, Class<? extends KeySpec> specType) throws IOException
    {
        // получить закодированное представление
        byte[] encoded = privateKey.getEncoded(); if (encoded == null)
        {
            // проверить наличие представления
            throw new UnsupportedOperationException();
        }
        // проверить требуемый формат
        if (specType.isAssignableFrom(PKCS8EncodedKeySpec.class))
        {
            // вернуть закодированное представление
            return new PKCS8EncodedKeySpec(encoded); 
        }
        return null; 
    }
}
