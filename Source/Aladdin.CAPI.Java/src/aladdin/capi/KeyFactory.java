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
        throws InvalidParameterSpecException
    {
        // проверить тип данных
        if (paramSpec instanceof IParameters) return (IParameters)paramSpec; 
        
        // выбросить исключение
        throw new InvalidParameterSpecException(); 
    }
    // создать открытый ключ
    public IPublicKey createPublicKey(KeySpec keySpec) 
        throws InvalidKeySpecException, IOException
    {
        // проверить тип данных
        if (!(keySpec instanceof EncodedKeySpec)) throw new InvalidKeySpecException(); 
        
        // выполнить преобразование типа
        EncodedKeySpec encodedKeySpec = (EncodedKeySpec)keySpec; 
            
        // проверить формат данных
        if (!encodedKeySpec.getFormat().equals("X.509")) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeySpecException();         
        }
        // раскодировать данные
        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(
            Encodable.decode(encodedKeySpec.getEncoded())
        ); 
        // извлечь идентификатор открытого ключа
        String keyOID = publicKeyInfo.algorithm().algorithm().value(); 
        
        // проверить совпадение идентификатора
        if (!keyOID.equals(keyOID())) throw new InvalidKeySpecException(); 
            
        // раскодировать открытый ключ
        return decodePublicKey(publicKeyInfo); 
    }
    // извлечь данные открытого ключа
    public KeySpec getPublicKeySpec(IPublicKey publicKey, 
        Class<? extends KeySpec> specType) throws InvalidKeySpecException
    {
        // получить закодированное представление
        SubjectPublicKeyInfo publicKeyInfo = publicKey.encoded(); 
        
        // проверить наличие представления
        if (publicKeyInfo == null) throw new UnsupportedOperationException();
        
        // проверить требуемый формат
        if (specType.isAssignableFrom(X509EncodedKeySpec.class))
        {
            // вернуть закодированное представление
            return new X509EncodedKeySpec(publicKeyInfo.encoded()); 
        }
        // при ошибке выбросить исключение
        throw new InvalidKeySpecException(); 
    }
    // создать личный ключ
    public IPrivateKey createPrivateKey(Factory factory, KeySpec keySpec) 
        throws InvalidKeySpecException, IOException
    {
        // проверить тип данных
        if (!(keySpec instanceof EncodedKeySpec)) throw new InvalidKeySpecException(); 
        
        // выполнить преобразование типа
        EncodedKeySpec encodedKeySpec = (EncodedKeySpec)keySpec; 
            
        // проверить формат данных
        if (!encodedKeySpec.getFormat().equals("PKCS#8")) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeySpecException(); 
        }
        // раскодировать данные
        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
            Encodable.decode(encodedKeySpec.getEncoded())
        ); 
        // извлечь идентификатор открытого ключа
        String keyOID = privateKeyInfo.privateKeyAlgorithm().algorithm().value(); 
            
        // проверить совпадение идентификатора
        if (!keyOID.equals(keyOID())) throw new InvalidKeySpecException(); 
        
        // раскодировать личный ключ
        return decodePrivateKey(factory, privateKeyInfo); 
    }
    // извлечь данные личного ключа
    public KeySpec getPrivateKeySpec(IPrivateKey privateKey, 
        Class<? extends KeySpec> specType) throws InvalidKeySpecException, IOException 
    {
        // получить закодированное представление
        PrivateKeyInfo privateKeyInfo = encodePrivateKey(privateKey, null); 
        
        // проверить наличие представления
        if (privateKeyInfo == null) throw new UnsupportedOperationException();
            
        // проверить требуемый формат
        if (specType.isAssignableFrom(PKCS8EncodedKeySpec.class))
        {
            // вернуть закодированное представление
            return new PKCS8EncodedKeySpec(privateKeyInfo.encoded()); 
        }
        // при ошибке выбросить исключение
        throw new InvalidKeySpecException(); 
    }
}
