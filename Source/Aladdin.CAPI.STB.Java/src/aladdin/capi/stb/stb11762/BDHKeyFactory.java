package aladdin.capi.stb.stb11762;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.stb.*;
import aladdin.capi.*; 
import java.security.spec.*;
import javax.crypto.spec.*;
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Параметры алгоритма обмена СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDHKeyFactory extends KeyFactory
{
    // конструктор
    public BDHKeyFactory(String keyOID) { this.keyOID = keyOID; }

    // идентификаторы открытых ключей
    @Override public String keyOID() { return keyOID; } private final String keyOID; 
    
	// способ использования ключа
	@Override public KeyUsage getKeyUsage() 
    { 
        // указать способ использования ключа
        return new KeyUsage(KeyUsage.KEY_ENCIPHERMENT);
    }
    // закодировать параметры
    @Override public IEncodable encodeParameters(aladdin.capi.IParameters parameters)
    {
        // указать приведение типа
        Tag tag = Tag.context(1); IEncodable encoded; 
        
        // для именованных параметров
        if (parameters instanceof INamedParameters) 
        { 
            // извлечь значение идентификатора
            String oid = ((INamedParameters)parameters).oid(); 
            
            // закодировать идентификатор
            encoded = new ObjectIdentifier(oid); 
        }
        else { 
            // преобразовать тип параметров
            IBDHParameters bdhParameters = (IBDHParameters)parameters; 

            // закодировать отдельные параметры
            Integer bdhL = new Integer(bdhParameters.bdhL()); 
            Integer bdhR = new Integer(bdhParameters.bdhR()); 
            Integer bdhP = new Integer(bdhParameters.bdhP()); 
            Integer bdhG = new Integer(bdhParameters.bdhG()); 
            Integer bdhN = new Integer(bdhParameters.bdhN()); 

            // закодировать параметры
            encoded = new BDHParamsList(bdhL, bdhR, bdhP, bdhG, bdhN, null);   
        }
        // выполнить преобразование типа
        return new Explicit<IEncodable>(IEncodable.class, tag, encoded); 
    }
    // раскодировать параметры
    @Override public IBDHParameters decodeParameters(IEncodable encodable) throws IOException
    {
        // проверить тип параметров
        if (!encodable.tag().equals(Tag.context(1))) throw new IOException(); 
        
        // раскодировать параметры
        IEncodable parameters = Encodable.decode(encodable.content());
        
        // при указании идентификатора
        if (parameters.tag().equals(Tag.OBJECTIDENTIFIER)) 
        {
            // раскодировать идентификатор
            ObjectIdentifier oid = new ObjectIdentifier(parameters); 
            
            // вернуть раскодированные параметры
            return new BDHNamedParameters(oid.value(), 
                BDHParamsList.parameters(oid.value())
            );
        }
        // вернуть раскодированные параметры
        else return new BDHParameters(new BDHParamsList(parameters)); 
    }
    // закодировать открытый ключ
    @Override public SubjectPublicKeyInfo encodePublicKey(IPublicKey publicKey)
    {
        // выполнить преобразование типа
        IBDHParameters parameters = (IBDHParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IBDHPublicKey bdhPublicKey = (IBDHPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
		// закодировать значение ключа
		BitString encoded = new BitString(new Integer(bdhPublicKey.bdhY()).encoded()); 
        
        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(algorithm, encoded); 
    }
    // раскодировать открытый ключ
    @Override public aladdin.capi.IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException
    {
        // раскодировать параметры
        IBDHParameters parameters = decodeParameters(encoded.algorithm().parameters()); 
        
		// раскодировать значение открытого ключа
        BigInteger y = new Integer(Encodable.decode(encoded.subjectPublicKey().value())).value(); 
        
        // вернуть открытый ключ
        return new BDHPublicKey(this, parameters, y); 
    }
    // закодировать личный ключ
    @Override public PrivateKeyInfo encodePrivateKey(
        aladdin.capi.IPrivateKey privateKey, Attributes attributes)
    {
        // выполнить преобразование типа
        IBDHParameters parameters = (IBDHParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IBDHPrivateKey bdhPrivateKey = (IBDHPrivateKey)privateKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
        // закодировать значение ключа
        OctetString encoded = new OctetString(new Integer(bdhPrivateKey.bdhX()).encoded());
        
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), algorithm, encoded, attributes); 
    }
    // раскодировать личный ключ
    @Override public aladdin.capi.IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException
    {
        // раскодировать параметры
        IBDHParameters parameters = decodeParameters(
            encoded.privateKeyAlgorithm().parameters()
        ); 
		// раскодировать значение личного ключа
		BigInteger x = new Integer(Encodable.decode(encoded.privateKey().value())).value(); 
        
        // вернуть личный ключ
        return new BDHPrivateKey(factory, null, keyOID, parameters, x); 
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
    @Override public KeyPair decodeKeyPair(Factory factory, 
        PrivateKeyInfo encoded) throws IOException
    {
        // раскодировать личный ключ
        try (IBDHPrivateKey privateKey = (IBDHPrivateKey)decodePrivateKey(factory, encoded))
        {  
            // преобразовать тип параметров
            IBDHParameters bdhParameters = (IBDHParameters)privateKey.parameters(); 

            // указать группу Монтгомери
            aladdin.math.Fp.MontGroup group = new aladdin.math.Fp.MontGroup(bdhParameters.bdhP()); 

            // вычислить открытый ключ
		    BigInteger Y = group.power(bdhParameters.bdhG(), privateKey.bdhX());

            // создать объект открытого ключа 
            IPublicKey publicKey = new BDHPublicKey(this, bdhParameters, Y);

            // вернуть пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
    } 
    // создать параметры
    @Override public aladdin.capi.IParameters createParameters(
        AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException
    {
        // создать параметры
        return BDHParameters.getInstance(paramSpec); 
    }
    // извлечь данные открытого ключа
    @Override public KeySpec getPublicKeySpec(
        aladdin.capi.IPublicKey publicKey, Class<? extends KeySpec> specType)
        throws InvalidKeySpecException
    {
        // выполнить преобразование типа
        IBDHParameters parameters = (IBDHParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IBDHPublicKey bdhPublicKey = (IBDHPublicKey)publicKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DHPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new DHPublicKeySpec(bdhPublicKey.bdhY(), 
                parameters.bdhP(), parameters.bdhG()
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
        IBDHParameters parameters = (IBDHParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IBDHPrivateKey bdhPrivateKey = (IBDHPrivateKey)privateKey; 
        
        // проверить требуемый тип данных
        if (specType.isAssignableFrom(DHPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new DHPrivateKeySpec(bdhPrivateKey.bdhX(), 
                parameters.bdhP(), parameters.bdhG()
            ); 
        }
        // вызвать базовую функцию
        return super.getPrivateKeySpec(privateKey, specType); 
    }
}
