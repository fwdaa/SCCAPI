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
// Параметры алгоритма подписи и обмена СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDSBDHKeyFactory extends KeyFactory
{
    // конструктор
    public BDSBDHKeyFactory(String keyOID) { this.keyOID = keyOID; }

    // идентификаторы открытых ключей
    @Override public String keyOID() { return keyOID; } private final String keyOID; 
    
	// способ использования ключа
	@Override public KeyUsage getKeyUsage() 
    { 
        // указать способ использования ключа
        return new KeyUsage(KeyUsage.DIGITAL_SIGNATURE | 
            KeyUsage.CERTIFICATE_SIGNATURE | KeyUsage.CRL_SIGNATURE | 
            KeyUsage.NON_REPUDIATION       | KeyUsage.KEY_ENCIPHERMENT
        );
    }
    // закодировать параметры
    @Override public IEncodable encodeParameters(aladdin.capi.IParameters parameters)
    {
        // указать приведение типа
        Tag tag = Tag.context(2); IEncodable encoded; 
        
        // для именованных параметров
        if (parameters instanceof INamedParameters) 
        { 
            // извлечь значение идентификатора
            String oid = ((INamedParameters)parameters).oid(); 
            
            // закодировать идентификатор
            encoded = new ObjectIdentifier(oid); 

            // выполнить преобразование типа
            return new Explicit<ObjectIdentifier>(
                ObjectIdentifier.class, Tag.context(2), encoded
            ); 
        }
        else { 
            // преобразовать тип параметров
            IBDSParameters bdsParameters = (IBDSBDHParameters)parameters; 
            IBDHParameters bdhParameters = (IBDSBDHParameters)parameters; 

            // закодировать отдельные параметры
            Integer     bdsL = new Integer    (bdsParameters.bdsL()); 
            Integer     bdsR = new Integer    (bdsParameters.bdsR()); 
            Integer     bdsP = new Integer    (bdsParameters.bdsP()); 
            Integer     bdsQ = new Integer    (bdsParameters.bdsQ()); 
            Integer     bdsA = new Integer    (bdsParameters.bdsA()); 
            OctetString bdsH = new OctetString(bdsParameters.bdsH());  

            // закодировать отдельные параметры
            Integer bdhL = new Integer(bdhParameters.bdhL()); 
            Integer bdhR = new Integer(bdhParameters.bdhR()); 
            Integer bdhP = new Integer(bdhParameters.bdhP()); 
            Integer bdhG = new Integer(bdhParameters.bdhG()); 
            Integer bdhN = new Integer(bdhParameters.bdhN()); 

            // закодировать набор параметров
            BDSParamsList signList = new BDSParamsList(
                bdsL, bdsR, bdsP, bdsQ, bdsA, bdsH, null
            );   
            // закодировать набор параметров
            BDHParamsList keyxList = new BDHParamsList(
                bdhL, bdhR, bdhP, bdhG, bdhN, null
            );
            // объединить наборы параметров
            encoded = new BDSBDHParamsList(signList, keyxList); 
        }
        // выполнить преобразование типа
        return new Explicit<IEncodable>(IEncodable.class, tag, encoded); 
    }
    // раскодировать параметры
    @Override public IBDSBDHParameters decodeParameters(IEncodable encodable) throws IOException
    {
        // проверить тип параметров
        if (!encodable.tag().equals(Tag.context(2))) throw new IOException(); 
        
        // раскодировать параметры
        IEncodable parameters = Encodable.decode(encodable.content());
        
        // при указании идентификатора
        if (parameters.tag().equals(Tag.OBJECTIDENTIFIER)) 
        {
            // раскодировать идентификатор
            ObjectIdentifier oid = new ObjectIdentifier(parameters); 
            
            // вернуть раскодированные параметры
            return new BDSBDHNamedParameters(oid.value(), 
                BDSBDHParamsList.parameters(oid.value())
            );
        }
        // раскодировать параметры
        else return new BDSBDHParameters(new BDSBDHParamsList(parameters)); 
    }
    // закодировать открытый ключ
    @Override public SubjectPublicKeyInfo encodePublicKey(aladdin.capi.IPublicKey publicKey)
    {
        // выполнить преобразование типа
        IBDSBDHParameters parameters = (IBDSBDHParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IBDSBDHPublicKey bdshPublicKey = (IBDSBDHPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
        // объединить значения ключей
        BDSBDHKeyValue encodedKey = new BDSBDHKeyValue(
            new Integer(bdshPublicKey.bdsY()), 
            new Integer(bdshPublicKey.bdhY())
        );
        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(algorithm, new BitString(encodedKey.encoded())); 
    }
    // раскодировать открытый ключ
    @Override public aladdin.capi.IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException
    {
        // раскодировать параметры
        IBDSBDHParameters parameters = decodeParameters(encoded.algorithm().parameters()); 
        
		// раскодировать значение открытого ключа
        BDSBDHKeyValue decodedKey = new BDSBDHKeyValue(
            Encodable.decode(encoded.subjectPublicKey().value())
        ); 
        // извлечь компоненты открытого ключа
        BigInteger bdsY = decodedKey.bdsKey().value(); 
        BigInteger bdhY = decodedKey.bdhKey().value();
        
        // вернуть открытый ключ
        return new BDSBDHPublicKey(this, parameters, bdsY, bdhY); 
    }
    // закодировать личный ключ
    @Override public PrivateKeyInfo encodePrivateKey(
        aladdin.capi.IPrivateKey privateKey, Attributes attributes)
    {
        // выполнить преобразование типа
        IBDSBDHParameters parameters = (IBDSBDHParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IBDSBDHPrivateKey bdshPrivateKey = (IBDSBDHPrivateKey)privateKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
        // объединить значения ключей
        BDSBDHKeyValue encodedKey = new BDSBDHKeyValue(
            new Integer(bdshPrivateKey.bdsX()), 
            new Integer(bdshPrivateKey.bdhX())
        ); 
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), 
            algorithm, new OctetString(encodedKey.encoded()), attributes
        ); 
    }
    @Override public aladdin.capi.IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException
    {
        // раскодировать параметры
        IBDSBDHParameters parameters = decodeParameters(
            encoded.privateKeyAlgorithm().parameters()
        ); 
		// раскодировать значение личного ключа
        BDSBDHKeyValue keyValue = new BDSBDHKeyValue(
            Encodable.decode(encoded.privateKey().value())
        ); 
        // извлечь компоненты личного ключа
        BigInteger bdsX = keyValue.bdsKey().value(); 
        BigInteger bdhX = keyValue.bdhKey().value();
        
        // вернуть личный ключ
        return new BDSBDHPrivateKey(factory, null, keyOID, parameters, bdsX, bdhX); 
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
        try (IBDSBDHPrivateKey privateKey = (IBDSBDHPrivateKey)decodePrivateKey(factory, encoded))
        {  
            // преобразовать тип параметров
            IBDSParameters bdsParameters = (IBDSParameters)privateKey.parameters(); 
            IBDHParameters bdhParameters = (IBDHParameters)privateKey.parameters(); 

            // указать группу Монтгомери
            aladdin.math.Fp.MontGroup bdsGroup = new aladdin.math.Fp.MontGroup(bdsParameters.bdsP()); 
            aladdin.math.Fp.MontGroup bdhGroup = new aladdin.math.Fp.MontGroup(bdhParameters.bdhP()); 

            // вычислить открытый ключ
		    BigInteger bdsY = bdsGroup.power(
                bdsParameters.bdsA(), ((IBDSPrivateKey)privateKey).bdsX()
            );
		    BigInteger bdhY = bdhGroup.power(
                bdhParameters.bdhG(), ((IBDHPrivateKey)privateKey).bdhX()
            );
            // создать объект открытого ключа 
            IPublicKey publicKey = new BDSBDHPublicKey(this, 
                (IBDSBDHParameters)privateKey.parameters(), bdsY, bdhY
            );
            // вернуть пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
    } 
    // создать параметры
    @Override public aladdin.capi.IParameters createParameters(
        AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException, IOException 
    { 
        // в зависимости от типа данных
        if (paramSpec instanceof DSAParameterSpec)
        {
            // выполнить преобразование типа
            if (paramSpec instanceof IParameters) return (IParameters)paramSpec; 
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
        IBDSBDHParameters bdshParameters = (IBDSBDHParameters)parameters; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DSAParameterSpec.class))
        {
            // в зависимости от типа данных
            if (bdshParameters instanceof DSAParameterSpec)
            {
                // выполнить преобразование типа
                return (DSAParameterSpec)bdshParameters; 
            }
            // вернуть параметры ключа
            return new DSAParameterSpec(bdshParameters.bdsP(), 
                bdshParameters.bdsQ(), bdshParameters.bdsA()
            ); 
        }
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DHParameterSpec.class))
        {
            // вернуть параметры ключа
            return new DHParameterSpec(bdshParameters.bdhP(), 
                bdshParameters.bdhG(), bdshParameters.bdhN()
            ); 
        }
        // вызвать базовую функцию
        return super.getParametersSpec(parameters, specType); 
    } 
    // извлечь данные ключа
    @Override public KeySpec getPublicKeySpec(
        aladdin.capi.IPublicKey publicKey, Class<? extends KeySpec> specType)
    {
        // выполнить преобразование типа
        IBDSBDHParameters parameters = (IBDSBDHParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IBDSBDHPublicKey bdshPublicKey = (IBDSBDHPublicKey)publicKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DSAPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new DSAPublicKeySpec(bdshPublicKey.bdsY(), 
                parameters.bdsP(), parameters.bdsQ(), parameters.bdsA()
            ); 
        }
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DHPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new DHPublicKeySpec(bdshPublicKey.bdhY(), 
                parameters.bdhP(), parameters.bdhG()
            ); 
        }
        // вызвать базовую функцию
        return super.getPublicKeySpec(publicKey, specType); 
    }
    // извлечь данные ключа
    @Override public KeySpec getPrivateKeySpec(
        aladdin.capi.IPrivateKey privateKey, 
        Class<? extends KeySpec> specType) throws IOException
    {
        // выполнить преобразование типа
        IBDSBDHParameters parameters = (IBDSBDHParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IBDSBDHPrivateKey bdshPrivateKey = (IBDSBDHPrivateKey)privateKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DSAPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new DSAPrivateKeySpec(bdshPrivateKey.bdsX(), 
                parameters.bdsP(), parameters.bdsQ(), parameters.bdsA()
            ); 
        }
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DHPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new DHPrivateKeySpec(bdshPrivateKey.bdhX(), 
                parameters.bdhP(), parameters.bdhG()
            ); 
        }
        // вызвать базовую функцию
        return super.getPrivateKeySpec(privateKey, specType); 
    }
}
