package aladdin.capi.stb.stb11762;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.stb.*;
import aladdin.capi.*; 
import java.security.spec.*;
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Параметры алгоритма подписи СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDSKeyFactory extends KeyFactory
{
    // конструктор
    public BDSKeyFactory(String keyOID) { this.keyOID = keyOID; }

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
    @Override public IEncodable encodeParameters(aladdin.capi.IParameters parameters)
    {
        // указать приведение типа
        Tag tag = Tag.context(0); IEncodable encoded; 
        
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
            IBDSParameters bdsParameters = (IBDSParameters)parameters; 

            // закодировать отдельные параметры
            Integer     bdsL = new Integer    (bdsParameters.bdsL()); 
            Integer     bdsR = new Integer    (bdsParameters.bdsR()); 
            Integer     bdsP = new Integer    (bdsParameters.bdsP()); 
            Integer     bdsQ = new Integer    (bdsParameters.bdsQ()); 
            Integer     bdsA = new Integer    (bdsParameters.bdsA()); 
            OctetString bdsH = new OctetString(bdsParameters.bdsH());
            
            // закодировать параметры
            encoded = new BDSParamsList(bdsL, bdsR, bdsP, bdsQ, bdsA, bdsH, null);   
        }
        // выполнить преобразование типа
        return new Explicit<IEncodable>(IEncodable.class, tag, encoded); 
    }
    // раскодировать параметры
    @Override public IBDSParameters decodeParameters(IEncodable encodable) throws IOException
    {
        // проверить тип параметров
        if (!encodable.tag().equals(Tag.context(0))) throw new IOException(); 
        
        // раскодировать параметры
        IEncodable parameters = Encodable.decode(encodable.content());
        
        // при указании идентификатора
        if (parameters.tag().equals(Tag.OBJECTIDENTIFIER)) 
        {
            // раскодировать идентификатор
            ObjectIdentifier oid = new ObjectIdentifier(parameters); 
            
            // вернуть раскодированные параметры
            return new BDSNamedParameters(oid.value(), 
                BDSParamsList.parameters(oid.value())
            );
        }
        // вернуть раскодированные параметры
        else return new BDSParameters(new BDSParamsList(parameters)); 
    }
    // закодировать открытый ключ
    @Override public SubjectPublicKeyInfo encodePublicKey(aladdin.capi.IPublicKey publicKey)
    {
        // выполнить преобразование типа
        IBDSParameters parameters = (IBDSParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IBDSPublicKey bdsPublicKey = (IBDSPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
        // закодировать значение ключа
        BitString encoded = new BitString(new Integer(bdsPublicKey.bdsY()).encoded());

        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(algorithm, encoded); 
    }
    // раскодировать открытый ключ
    @Override public aladdin.capi.IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException
    {
        // раскодировать параметры
        IBDSParameters parameters = decodeParameters(encoded.algorithm().parameters()); 
        
		// раскодировать значение открытого ключа
        BigInteger y = new Integer(Encodable.decode(encoded.subjectPublicKey().value())).value(); 
        
        // вернуть открытый ключ
        return new BDSPublicKey(this, parameters, y); 
    }
    // закодировать личный ключ
    @Override public PrivateKeyInfo encodePrivateKey(
        aladdin.capi.IPrivateKey privateKey, Attributes attributes)
    {
        // выполнить преобразование типа
        IBDSParameters parameters = (IBDSParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IBDSPrivateKey bdsPrivateKey = (IBDSPrivateKey)privateKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
        // закодировать значение ключа
        OctetString encoded = new OctetString(new Integer(bdsPrivateKey.bdsX()).encoded());
        
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), algorithm, encoded, attributes); 
    }
    // раскодировать личный ключ
    @Override public aladdin.capi.IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException
    {
        // раскодировать параметры
        IBDSParameters parameters = decodeParameters(
            encoded.privateKeyAlgorithm().parameters()
        ); 
		// раскодировать значение личного ключа
		BigInteger x = new Integer(Encodable.decode(encoded.privateKey().value())).value(); 
        
        // вернуть личный ключ
        return new BDSPrivateKey(factory, null, keyOID, parameters, x); 
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
        try (IBDSPrivateKey privateKey = (IBDSPrivateKey)decodePrivateKey(factory, encoded))
        {  
            // преобразовать тип параметров
            IBDSParameters bdsParameters = (IBDSParameters)privateKey.parameters(); 

            // указать группу Монтгомери
            aladdin.math.Fp.MontGroup group = new aladdin.math.Fp.MontGroup(bdsParameters.bdsP()); 

	        // вычислить открытый ключ
	        BigInteger Y = group.power(bdsParameters.bdsA(), privateKey.bdsX());

            // создать объект открытого ключа 
            IPublicKey publicKey = new BDSPublicKey(this, bdsParameters, Y);

            // вернуть пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
    } 
    // создать параметры
    @Override public aladdin.capi.IParameters createParameters(
        AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException
    {
        // создать параметры
        return BDSParameters.getInstance(paramSpec); 
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
            
            // вычислить параметры L и R
            int l = dsaKeySpec.getP().bitLength(); 
            int r = dsaKeySpec.getQ().bitLength(); 
            
            // создать параметры ключа
            BDSParameters parameters = new BDSParameters(l, r, 
                dsaKeySpec.getP(), dsaKeySpec.getQ(), dsaKeySpec.getG(), 
                new byte[32], null
            ); 
            // создать открытый ключ
            return new BDSPublicKey(this, parameters, dsaKeySpec.getY()); 
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
        IBDSParameters parameters = (IBDSParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IBDSPublicKey bdsPublicKey = (IBDSPublicKey)publicKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DSAPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new DSAPublicKeySpec(bdsPublicKey.bdsY(), 
                parameters.bdsP(), parameters.bdsQ(), parameters.bdsA()
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
            
            // вычислить параметры L и R
            int l = dsaKeySpec.getP().bitLength(); 
            int r = dsaKeySpec.getQ().bitLength(); 
            
            // создать параметры ключа
            BDSParameters parameters = new BDSParameters(l, r, 
                dsaKeySpec.getP(), dsaKeySpec.getQ(), dsaKeySpec.getG(), 
                new byte[32], null
            ); 
            // создать личный ключ
            return new BDSPrivateKey(factory, 
                null, keyOID, parameters, dsaKeySpec.getX()
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
        IBDSParameters parameters = (IBDSParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IBDSPrivateKey bdsPrivateKey = (IBDSPrivateKey)privateKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DSAPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new DSAPrivateKeySpec(bdsPrivateKey.bdsX(), 
                parameters.bdsP(), parameters.bdsQ(), parameters.bdsA()
            ); 
        }
        // вызвать базовую функцию
        return super.getPrivateKeySpec(privateKey, specType); 
    }
}
