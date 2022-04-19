package aladdin.capi.ansi.x962;
 import aladdin.math.*;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.ansi.x962.*;
import aladdin.capi.*; 
import aladdin.capi.ec.*; 
import java.security.spec.*; 
import java.math.*;
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
// Фабрика кодирования кючей
////////////////////////////////////////////////////////////////////////////////
public class KeyFactory extends aladdin.capi.KeyFactory
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
        
    // конструктор
    public KeyFactory(String keyOID) { this.keyOID = keyOID; }

    // идентификаторы поддерживаемых ключей
    @Override public String keyOID() { return keyOID; } private final String keyOID; 
    
	// способ использования ключа
	@Override public KeyUsage getKeyUsage() 
    { 
        // указать способ использования ключа
        return new KeyUsage(KeyUsage.DIGITAL_SIGNATURE | 
            KeyUsage.CERTIFICATE_SIGNATURE | KeyUsage.CRL_SIGNATURE | 
            KeyUsage.NON_REPUDIATION       | KeyUsage.KEY_AGREEMENT
        );
    }
    // закодировать параметры
    @Override public IEncodable encodeParameters(aladdin.capi.IParameters parameters)
    {
        // закодировать параметры
        return encodeParameters(parameters, Encoding.UNCOMPRESSED, true); 
    }
    // закодировать параметры
    public IEncodable encodeParameters(
        aladdin.capi.IParameters parameters, Encoding encoding, boolean useOID) 
    {
        // при указании идентификатора 
        if (parameters instanceof INamedParameters && useOID)
        {
            // закодировать идентификатор параметров
            return new ObjectIdentifier(((INamedParameters)parameters).oid()); 
        }
        // преобразовать тип параметров
        aladdin.capi.ansi.x962.IParameters ecParameters = 
            (aladdin.capi.ansi.x962.IParameters)parameters; 
            
        // в зависимости от типа поля
        if (ecParameters.getCurve().getField() instanceof java.security.spec.ECFieldF2m)
        {
            // указать фабрику кодирования
            KeyFactory keyFactory = new aladdin.capi.ansi.x962.F2m.KeyFactory(keyOID); 
            
            // закодировать параметры
            return keyFactory.encodeParameters(parameters, encoding, useOID); 
        }
        else {
            // указать фабрику кодирования
            KeyFactory keyFactory = new aladdin.capi.ansi.x962.Fp.KeyFactory(keyOID); 
            
            // закодировать параметры
            return keyFactory.encodeParameters(parameters, encoding, useOID); 
        }
    }
    // раскодировать параметры
	@Override public IParameters decodeParameters(IEncodable encoded) throws IOException
    {
        // раскодировать параметры
        encoded = new ECDomainParameters().decode(encoded); 
        
        // проверить указание параметров
        if (encoded instanceof Null) throw new UnsupportedOperationException(); 
        
        // указать начальные условия
        String oid = null; SpecifiedECDomain parameters; 
        
        // при указании идентификатора
        if (encoded instanceof ObjectIdentifier)
        {
            // раскодировать идентификатор параметров
            oid = ((ObjectIdentifier)encoded).value(); 
            
            // получить набор параметров
            parameters = SpecifiedECDomain.parameters(oid); 
        }
        // получить набор параметров
        else parameters = (SpecifiedECDomain)encoded;
            
        // определить тип поля
        String fieldOID = parameters.fieldID().fieldType().value(); 
            
        // в зависимости от типа поля
        if (fieldOID.equals(aladdin.asn1.ansi.OID.X962_C2_FIELD))
        {
            // указать фабрику кодирования
            aladdin.capi.ansi.x962.F2m.KeyFactory keyFactory = 
                new aladdin.capi.ansi.x962.F2m.KeyFactory(keyOID); 
                
            // раскодировать параметры
            return keyFactory.decodeParameters(oid, parameters); 
        }
        else {
            // указать фабрику кодирования
            aladdin.capi.ansi.x962.Fp.KeyFactory keyFactory = 
                new aladdin.capi.ansi.x962.Fp.KeyFactory(keyOID); 
              
            // раскодировать параметры
            return keyFactory.decodeParameters(oid, parameters); 
        }
    }
    // закодировать открытый ключ
    @Override public final SubjectPublicKeyInfo encodePublicKey(
        aladdin.capi.IPublicKey publicKey) 
    {
        // закодировать открытый ключ
        return encodePublicKey(publicKey, Encoding.UNCOMPRESSED, true); 
    }
    // закодировать открытый ключ
    public final SubjectPublicKeyInfo encodePublicKey(
        aladdin.capi.IPublicKey publicKey, Encoding encoding, boolean useOID) 
    {
        // выполнить преобразование типа
        IParameters parameters = (IParameters)publicKey.parameters();
        
        // выполнить преобразование типа
        IPublicKey ecPublicKey = (IPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters, encoding, useOID)
		); 
		// закодировать значение ключа
		BitString encoded = new BitString(
            parameters.getCurve().encode(ecPublicKey.getW(), encoding)
        ); 
        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(algorithm, encoded); 
    }
    // раскодировать открытый ключ
    @Override public IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException 
    {
        // раскодировать параметры
        IParameters parameters = decodeParameters(encoded.algorithm().parameters()); 
        
        // раскодировать значение открытого ключа
		java.security.spec.ECPoint q = parameters.getCurve().decode(
            encoded.subjectPublicKey().value()
        ); 
        // вернуть открытый ключ
        return new PublicKey(this, parameters, q); 
    }
    // закодировать личный ключ
    @Override public final PrivateKeyInfo encodePrivateKey(
        aladdin.capi.IPrivateKey privateKey, Attributes attributes) throws IOException
    {
        // закодировать личный ключ
        return encodePrivateKey(privateKey, attributes, Encoding.UNCOMPRESSED, true); 
    }
    // закодировать личный ключ
    public final PrivateKeyInfo encodePrivateKey(aladdin.capi.IPrivateKey privateKey, 
        Attributes attributes, Encoding encoding, boolean useOID) throws IOException
    {
        // закодировать личный ключ
        return encodeKeyPair(privateKey, null, attributes, encoding, useOID); 
    }
    // раскодировать личный ключ
    @Override public IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException 
    {
        // указать закодированные параметры
        IEncodable encodedParameters = encoded.privateKeyAlgorithm().parameters(); 
        
        // раскодировать личный ключ
        ECPrivateKey decodedKey = new ECPrivateKey(
            Encodable.decode(encoded.privateKey().value())
        );
        // скорректировать параметры алгоритма
        if (decodedKey.parameters() != null) encodedParameters = decodedKey.parameters();
        
        // раскодировать параметры
        IParameters parameters = decodeParameters(encodedParameters); 
        
        // раскодировать значение личного ключа
        BigInteger d = Convert.toBigInteger(
            decodedKey.privateKey().value(), ENDIAN
        ); 
        // вернуть личный ключ
        return new PrivateKey(factory, null, keyOID, parameters, d); 
    }
    // закодировать пару ключей
	@Override public PrivateKeyInfo encodeKeyPair(aladdin.capi.IPrivateKey privateKey, 
        aladdin.capi.IPublicKey publicKey, Attributes attributes) throws IOException
    {
        // закодировать пару ключей
        return encodeKeyPair(privateKey, publicKey, attributes, Encoding.UNCOMPRESSED, true); 
    }
    // закодировать пару ключей
	public PrivateKeyInfo encodeKeyPair(aladdin.capi.IPrivateKey privateKey, 
        aladdin.capi.IPublicKey publicKey, Attributes attributes, 
        Encoding encoding, boolean useOID) throws IOException 
    {
        // выполнить преобразование типа
        IParameters parameters = (IParameters)privateKey.parameters(); 
        
        // выполнить преобразование типа
        IPrivateKey ecPrivateKey = (IPrivateKey)privateKey; 
        IPublicKey  ecPublicKey  = (IPublicKey )publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters, encoding, useOID)
		); 
        // закодировать большое число
        OctetString encodedD = new OctetString(Convert.fromBigInteger(ecPrivateKey.getS(), ENDIAN)); 
        
		// при наличии открытого ключа
		BitString encodedQ = null; if (publicKey != null)
        {
            // закодировать значение ключа
            encodedQ = new BitString(parameters.getCurve().encode(ecPublicKey.getW(), encoding)); 
        }
        // закодировать личный ключ
        ECPrivateKey encodedKey = new ECPrivateKey(
            new Integer(1), encodedD, algorithm.parameters(), encodedQ
        ); 
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), 
            algorithm, new OctetString(encodedKey.encoded()), attributes
        ); 
    }
	// раскодировать пару ключей
    @Override public KeyPair decodeKeyPair(Factory factory, PrivateKeyInfo encoded) throws IOException
    {
        // указать закодированные параметры
        IEncodable encodedParameters = encoded.privateKeyAlgorithm().parameters(); 
        
        // раскодировать личный ключ
        ECPrivateKey decodedKey = new ECPrivateKey(
            Encodable.decode(encoded.privateKey().value())
        );
        // скорректировать параметры алгоритма
        if (decodedKey.parameters() != null) encodedParameters = decodedKey.parameters();
        
        // раскодировать параметры
        IParameters parameters = decodeParameters(encodedParameters); 

        // раскодировать значение личного ключа
        BigInteger d = Convert.toBigInteger(decodedKey.privateKey().value(), ENDIAN); 
        
        // создать объект личного ключа
        try (IPrivateKey privateKey = new PrivateKey(
            factory, null, keyOID, parameters, d))
        {
            // при наличии открытого ключа
            if (decodedKey.publicKey() != null)
            {
                // раскодировать значение открытого ключа
                ECPoint q = parameters.getCurve().decode(
                    decodedKey.publicKey().value()
                ); 
                // создать открытый ключ
                IPublicKey publicKey = new PublicKey(this, parameters, q);
                
                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
            else { 
	            // вычислить открытый ключ
                ECPoint Q = parameters.getCurve().multiply(
                    parameters.getGenerator(), privateKey.getS()
                );		      
                // создать объект открытого ключа 
                IPublicKey publicKey = new PublicKey(this, parameters, Q);

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
        return Parameters.getInstance(paramSpec); 
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
            
            // получить параметры ключа
            ECParameterSpec ecParamSpec = ecKeySpec.getParams(); 
            
            // проверить требуемый тип данных
            if (ecParamSpec instanceof IParameters) 
            {
                // выполнить преобразование типа
                IParameters parameters = (IParameters)ecParamSpec; 
                
                // создать открытый ключ
                return new PublicKey(this, parameters, ecKeySpec.getW()); 
            }
            else {
                // преобразовать тип кривой
                aladdin.capi.ec.Curve curve = aladdin.capi.ec.Curve.convert(
                    ecParamSpec.getCurve()
                );
                // создать параметры ключа
                IParameters parameters = new Parameters(curve, 
                    ecParamSpec.getGenerator(), ecParamSpec.getOrder(), 
                    ecParamSpec.getCofactor(), null
                ); 
                // создать открытый ключ
                return new PublicKey(this, parameters, ecKeySpec.getW()); 
            }
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
        IPublicKey ecPublicKey = (IPublicKey)publicKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(ECPublicKeySpec.class))
        {
            // вернуть данные ключа
            return new ECPublicKeySpec(
                ecPublicKey.getW(), Parameters.convert(parameters)
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
        if (keySpec instanceof ECPrivateKeySpec)
        {
            // выполнить преобразование типа
            ECPrivateKeySpec ecKeySpec = (ECPrivateKeySpec)keySpec; 
            
            // получить параметры ключа
            ECParameterSpec ecParamSpec = ecKeySpec.getParams(); 
            
            // проверить требуемый тип данных
            if (ecParamSpec instanceof IParameters) 
            {
                // выполнить преобразование типа
                IParameters parameters = (IParameters)ecParamSpec; 
                
                // создать личный ключ
                return new PrivateKey(factory, null, keyOID, parameters, ecKeySpec.getS()); 
            }
            else {
                // преобразовать тип кривой
                aladdin.capi.ec.Curve curve = aladdin.capi.ec.Curve.convert(
                    ecParamSpec.getCurve()
                );
                // создать параметры ключа
                IParameters parameters = new Parameters(curve, 
                    ecParamSpec.getGenerator(), ecParamSpec.getOrder(), 
                    ecParamSpec.getCofactor(), null
                ); 
                // создать личный ключ
                return new PrivateKey(factory, null, keyOID, parameters, ecKeySpec.getS()); 
            }
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
        IPrivateKey ecPrivateKey = (IPrivateKey)privateKey; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(ECPrivateKeySpec.class))
        {
            // вернуть данные ключа
            return new ECPrivateKeySpec(ecPrivateKey.getS(), 
                Parameters.convert(parameters)
            ); 
        }
        // вызвать базовую функцию
        return super.getPrivateKeySpec(privateKey, specType); 
    }
}
