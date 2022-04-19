package aladdin.capi.stb.stb34101;
import aladdin.math.*;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.stb.*;
import aladdin.capi.*; 
import aladdin.capi.ec.*; 
import aladdin.util.*;
import java.security.spec.*; 
import java.math.*;
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
// Фабрика кодирования кючей
////////////////////////////////////////////////////////////////////////////////
public class KeyFactory extends aladdin.capi.KeyFactory
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 

    // конструктор
    public KeyFactory(String keyOID) { this.keyOID = keyOID; }

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
        // при указании идентификатора 
        if (parameters instanceof NamedParameters)
        {
            // закодировать идентификатор параметров
            return new ObjectIdentifier(((NamedParameters)parameters).oid()); 
        }
        else { 
            // преобразовать тип параметров
            IParameters stbParameters = (IParameters)parameters; 
            
            // проверить корректность данных
            if (stbParameters.getGenerator().getAffineX().signum() != 0) 
            {
                // при ошибке выбросить исключение
                throw new UnsupportedOperationException(); 
            }
            // получить параметры эллиптической кривой
            CurveFp ec = stbParameters.getCurve(); ECFieldFp field = ec.getField();
            
            // указать идентификатор типа поля
            ObjectIdentifier fieldType = new ObjectIdentifier(
                aladdin.asn1.stb.OID.STB34101_BIGN_PRIMEFIELD
            ); 
            // закодировать параметры поля
            FieldID fieldID = new FieldID(fieldType, new Integer(field.getP())); 
            
            // определить размер координат
            int l = stbParameters.getOrder().bitLength() / 2;

            // закодировать параметры a и b кривой
            byte[] A  = Convert.fromBigInteger(ec.getA(), ENDIAN, l / 4);
            byte[] B  = Convert.fromBigInteger(ec.getB(), ENDIAN, l / 4);
            
            // закодировать точку на эллиптической кривой
            byte[] GY = Convert.fromBigInteger(stbParameters.getGenerator().getAffineY(), ENDIAN, l / 4);
            
            // закодировать параметры эллиптичесой кривой
            aladdin.asn1.stb.Curve curve = new aladdin.asn1.stb.Curve(
                new OctetString(A), new OctetString(B), new BitString(ec.getSeed())
            ); 
            // закодировать параметры в целом
            return new ECParameters(new Integer(1), fieldID, curve, 
                new OctetString(GY), new Integer(stbParameters.getOrder()), null
            ); 
        }
    }
    // раскодировать параметры
    @Override public IParameters decodeParameters(IEncodable encoded) throws IOException 
    {
        // раскодировать параметры
        encoded = new DomainParameters().decode(encoded); 
        
        // проверить указание параметров
        if (encoded instanceof Null) throw new UnsupportedOperationException(); 
        
        // при указании идентификатора
        if (encoded instanceof ObjectIdentifier)
        {
            // раскодировать идентификатор параметров
            String oid = ((ObjectIdentifier)encoded).value(); 
            
            // раскодировать набор параметров
            return decodeParameters(oid, ECParameters.parameters(oid)); 
        }
        // раскодировать параметры
        else return decodeParameters(null, (ECParameters)encoded); 
    }
    // раскодировать параметры
    public IParameters decodeParameters(String oid, ECParameters parameters) throws IOException 
    {
        // проверить корректность параметров
        if (parameters.cofactor().value().intValue() != 1) throw new IOException(); 
        
        // раскодировать модуль простого поля
        BigInteger modulus = parameters.fieldID().parameters().value();
        
        // извлечь параметры эллиптической кривой
        aladdin.asn1.stb.Curve curve = parameters.curve(); byte[] seed = curve.seed().value(); 
        
        // раскодировать коэффициенты a и b
        BigInteger a = Convert.toBigInteger(curve.a().value(), ENDIAN); 
        BigInteger b = Convert.toBigInteger(curve.b().value(), ENDIAN); 
        
        // создать эллиптическую кривую
        CurveFp ec = new CurveFp(modulus, a, b, seed); 
        
        // раскодировать координаты базовой точки
        BigInteger gy = Convert.toBigInteger(parameters.base().value(), ENDIAN); 
        
        // создать базовую точку
        ECPoint g = new ECPoint(BigInteger.ZERO, gy); 
        
        // раскодировать порядок базовой точки
        BigInteger q = parameters.order().value(); if (oid == null)
        {
            // вернуть параметры алгоритма
            return new Parameters(ec, g, q); 
        }
        // вернуть параметры алгоритма
        else return new NamedParameters(oid, ec, g, q); 
    }
    // закодировать открытый ключ
    @Override public SubjectPublicKeyInfo encodePublicKey(aladdin.capi.IPublicKey publicKey) 
    {
        // выполнить преобразование типа
        IParameters parameters = (IParameters)publicKey.parameters(); 
        
        // выполнить преобразование типа
        IPublicKey ecPublicKey = (IPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
        // определить параметр l
        int l = parameters.getOrder().bitLength() / 2; 
        
        // закодировать координаты
        byte[] QX = Convert.fromBigInteger(ecPublicKey.getW().getAffineX(), ENDIAN, l / 4);
        byte[] QY = Convert.fromBigInteger(ecPublicKey.getW().getAffineY(), ENDIAN, l / 4);
        
        // закодировать значение ключа
        BitString encoded = new BitString(Array.concat(QX, QY));

        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(algorithm, encoded); 
    }
    // раскодировать открытый ключ
    @Override public aladdin.capi.IPublicKey decodePublicKey(
        SubjectPublicKeyInfo encoded) throws IOException 
    {
        // раскодировать параметры
        IParameters parameters = decodeParameters(encoded.algorithm().parameters()); 
        
        // определить параметр l
        int l = parameters.getOrder().bitLength() / 2; byte[] xy = encoded.subjectPublicKey().value(); 
        
        // проверить корректность размера
        if (xy.length != l / 2) throw new IOException(); 
        
        // раскодировать координаты
        BigInteger QX = Convert.toBigInteger(xy,     0, l / 4, ENDIAN); 
        BigInteger QY = Convert.toBigInteger(xy, l / 4, l / 4, ENDIAN); 
        
        // раскодировать значение открытого ключа
        ECPoint q = new ECPoint(QX, QY); 
        
        // вернуть открытый ключ
        return new PublicKey(this, parameters, q); 
    }
    // закодировать личный ключ
    @Override public PrivateKeyInfo encodePrivateKey(
        aladdin.capi.IPrivateKey privateKey, Attributes attributes) 
    {
        // выполнить преобразование типа
        IParameters parameters = (IParameters)privateKey.parameters();
        
        // выполнить преобразование типа
        IPrivateKey ecPrivateKey = (IPrivateKey)privateKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID), encodeParameters(parameters)
		); 
        // определить параметр l
        int l = parameters.getOrder().bitLength() / 2; 
        
        // закодировать значение личного ключа
        OctetString encoded = new OctetString(
            Convert.fromBigInteger(ecPrivateKey.getS(), ENDIAN, l / 4)
        );
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), algorithm, encoded, attributes); 
    }
    // раскодировать личный ключ
    @Override public aladdin.capi.IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException 
    {
        // раскодировать параметры
        IParameters parameters = decodeParameters(
            encoded.privateKeyAlgorithm().parameters()
        ); 
        // определить параметр l
        int l = parameters.getOrder().bitLength() / 2; 
        
        // звлечь закодированное представление
        byte[] encodedD = encoded.privateKey().value(); 
        
        // проверить корректность размера
        if (encodedD.length != l / 4) throw new IOException(); 
        
        // раскодировать значение личного ключа
        BigInteger d = Convert.toBigInteger(encodedD, ENDIAN); 
        
        // вернуть личный ключ
        return new PrivateKey(factory, null, keyOID, parameters, d); 
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
        try (IPrivateKey privateKey = (IPrivateKey)decodePrivateKey(factory, encoded))
        {  
            // преобразовать тип параметров
            IParameters ecParameters = (IParameters)privateKey.parameters(); 

            // вычислить открытый ключ
		    ECPoint Q = ecParameters.getCurve().multiply(
                ecParameters.getGenerator(), privateKey.getS()
            ); 
            // создать объект открытого ключа 
            IPublicKey publicKey = new PublicKey(this, ecParameters, Q);

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
        // проверить требуемый тип данных
        if (keySpec instanceof ECPublicKeySpec)
        {
            // выполнить преобразование типа
            ECPublicKeySpec ecKeySpec = (ECPublicKeySpec)keySpec; 
            
            // получить параметры 
            ECParameterSpec ecParamSpec = ecKeySpec.getParams(); 
            
            // проверить корректность параметров
            if (ecParamSpec.getCofactor() != 1) throw new InvalidKeySpecException(); 
            
            // в зависимости от типа параметров
            if (ecParamSpec instanceof IParameters)
            {            
                // выполнить преобразование типа
                IParameters parameters = (IParameters)ecParamSpec; 
                
                // создать открытый ключ
                return new PublicKey(this, parameters, ecKeySpec.getW()); 
            }
            try { 
                // преобразовать тип кривой
                CurveFp curve = CurveFp.convert(ecParamSpec.getCurve());
        
                // создать параметры ключа
                IParameters parameters = new Parameters(curve, 
                    ecParamSpec.getGenerator(), ecParamSpec.getOrder()
                ); 
                // создать открытый ключ
                return new PublicKey(this, parameters, ecKeySpec.getW()); 
            }
            // при возникновении ошибки
            catch (IllegalArgumentException e) 
            { 
                // изменить тип исключения
                throw new InvalidKeySpecException(e.getMessage()); 
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
            return new ECPublicKeySpec(ecPublicKey.getW(), 
                Parameters.convert(parameters)
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
        // проверить требуемый тип данных
        if (keySpec instanceof ECPrivateKeySpec)
        {
            // выполнить преобразование типа
            ECPrivateKeySpec ecKeySpec = (ECPrivateKeySpec)keySpec; 
            
            // получить параметры 
            ECParameterSpec ecParamSpec = ecKeySpec.getParams(); 
            
            // проверить корректность параметров
            if (ecParamSpec.getCofactor() != 1) throw new InvalidKeySpecException(); 
            
            // в зависимости от типа параметров
            if (ecParamSpec instanceof IParameters)
            {            
                // выполнить преобразование типа
                IParameters parameters = (IParameters)ecParamSpec; 
                
                // создать личный ключ
                return new PrivateKey(factory, null, keyOID, parameters, ecKeySpec.getS()); 
            }
            try { 
                // преобразовать тип кривой
                CurveFp curve = CurveFp.convert(ecParamSpec.getCurve());
        
                // создать параметры ключа
                IParameters parameters = new Parameters(curve, 
                    ecParamSpec.getGenerator(), ecParamSpec.getOrder()
                ); 
                // создать личный ключ
                return new PrivateKey(factory, null, keyOID, parameters, ecKeySpec.getS()); 
            }
            // при возникновении ошибки
            catch (IllegalArgumentException e) 
            { 
                // изменить тип исключения
                throw new InvalidKeySpecException(e.getMessage()); 
            }
        }
        // вызвать базовую функцию
        return super.createPrivateKey(factory, keySpec); 
    }
    // извлечь данные ключа
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
