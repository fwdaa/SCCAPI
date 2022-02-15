package aladdin.capi.kz.gost34310;
import aladdin.math.*; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.capi.*; 
import aladdin.capi.gost.gostr3410.*; 
import java.security.spec.*; 
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключа ГОСТ Р 34.10-2001
///////////////////////////////////////////////////////////////////////////
public class ECKeyFactory extends aladdin.capi.gost.gostr3410.ECKeyFactory
{
    // параметры ключа
    private ECNamedParameters parameters; 
    
    // конструктор
    public ECKeyFactory(String keyOID) { super(keyOID); 
        
        // в зависимсоти от идентификатор ключа
        if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_A)) 
        {
            // указать параметры ключа
            parameters = new ECNamedParameters(keyOID, aladdin.asn1.gost.OID.ECC_SIGNS_A); 
        }
        // в зависимсоти от идентификатор ключа
        else if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_B)) 
        {
            // указать параметры ключа
            parameters = new ECNamedParameters(keyOID, aladdin.asn1.gost.OID.ECC_SIGNS_B); 
        }
        // в зависимсоти от идентификатор ключа
        else if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_C)) 
        {
            // указать параметры ключа
            parameters = new ECNamedParameters(keyOID, aladdin.asn1.gost.OID.ECC_SIGNS_C); 
        }
        // в зависимсоти от идентификатор ключа
        else if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_A_XCH)) 
        {
            // указать параметры ключа
            parameters = new ECNamedParameters(keyOID, aladdin.asn1.gost.OID.ECC_EXCHANGES_A); 
        }
        // в зависимсоти от идентификатор ключа
        else if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_B_XCH)) 
        {
            // указать параметры ключа
            parameters = new ECNamedParameters(keyOID, aladdin.asn1.gost.OID.ECC_EXCHANGES_B); 
        }
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException(); 
    } 
    // способ использования ключа
	@Override public KeyUsage getKeyUsage() 
	{
        // для специальных ключей
        if (keyOID().equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_A_XCH) || 
            keyOID().equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_B_XCH))
        {
            // указать способ использования ключа
            return new KeyUsage(KeyUsage.KEY_AGREEMENT | 
                KeyUsage.DIGITAL_SIGNATURE | KeyUsage.CERTIFICATE_SIGNATURE | 
                KeyUsage.CRL_SIGNATURE     | KeyUsage.NON_REPUDIATION        
            );
        }
        else {
            // указать способ использования ключа
            return new KeyUsage(
                KeyUsage.DIGITAL_SIGNATURE | KeyUsage.CERTIFICATE_SIGNATURE | 
                KeyUsage.CRL_SIGNATURE     | KeyUsage.NON_REPUDIATION
            );
        }
    }
    // закодировать параметры
    @Override public IEncodable encodeParameters(
        aladdin.capi.IParameters parameters) { return Null.INSTANCE; }
    
    // параметры алгоритма
    @Override public final ECNamedParameters 
        decodeParameters(IEncodable encoded) { return parameters; }
    
	// закодировать открытый ключ
	@Override public SubjectPublicKeyInfo encodePublicKey(IPublicKey publicKey)
    {
        // выполнить преобразование типа
        IECPublicKey ecPublicKey = (IECPublicKey)publicKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID()), Null.INSTANCE
		); 
	    // выделить буфер требуемого размера
        byte[] blob = new byte[80]; byte[] header = new byte[] {
            0x06, 0x02, 0x00, 0x00, // PUBLICKEYBLOB
            0x00, 0x00, 0x00, 0x00, // AlgID
            0x00, 0x45, 0x43, 0x31, // EC1
            0x00, 0x02, 0x00, 0x00, // 512 бит
        }; 
        // в зависимости от идентификатора
        if (keyOID().equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_A)) 
        { 
            // указать идентификатор ключа
            header[4] = 0x3A; header[5] = (byte)0xAA; 
        } 
        // в зависимости от идентификатора
        else if (keyOID().equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_B)) 
        { 
            // указать идентификатор ключа
            header[4] = 0x40; header[5] = (byte)0xAA; 
        } 
        // в зависимости от идентификатора
        else if (keyOID().equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_C)) 
        { 
            // указать идентификатор ключа
            header[4] = 0x41; header[5] = (byte)0xAA; 
        } 
        // в зависимости от идентификатора
        else if (keyOID().equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_A_XCH)) 
        { 
            // указать идентификатор ключа
            header[4] = 0x45; header[5] = (byte)0xA0; 
        } 
        // в зависимости от идентификатора
        else if (keyOID().equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_B_XCH)) 
        { 
            // указать идентификатор ключа
            header[4] = 0x46; header[5] = (byte)0xA0; 
        } 
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException(); 
        
        // скопировать сформированный заголовок в буфер
        System.arraycopy(header, 0, blob, 0, header.length); 
            
		// закодировать координаты точки
		Convert.fromBigInteger(ecPublicKey.getW().getAffineX(), Endian.LITTLE_ENDIAN, blob, 16, 32); 
		Convert.fromBigInteger(ecPublicKey.getW().getAffineY(), Endian.LITTLE_ENDIAN, blob, 48, 32); 

        // вернуть закодированное представление
        return new SubjectPublicKeyInfo(algorithm, new BitString(blob)); 
    }
    // раскодировать открытый ключ
	@Override public IPublicKey decodePublicKey(SubjectPublicKeyInfo encoded) throws IOException
    {
        // выделить буфер для координат точек
        byte[] x = new byte[32]; byte[] y = new byte[32]; 
        
        // скопировать координаты точки
		System.arraycopy(encoded.subjectPublicKey().value(), 16, x, 0, x.length); 
		System.arraycopy(encoded.subjectPublicKey().value(), 48, y, 0, y.length); 

		// раскодировать координаты точки
		BigInteger X = Convert.toBigInteger(x, Endian.LITTLE_ENDIAN); 
		BigInteger Y = Convert.toBigInteger(y, Endian.LITTLE_ENDIAN); 

		// создать точку эллиптической кривой
		ECPoint q = new ECPoint(X, Y); 

		// создать открытый ключ
		return new ECPublicKey(this, parameters, q); 
    }
    // закодировать личный ключ
	@Override public PrivateKeyInfo encodePrivateKey(
        IPrivateKey privateKey, Attributes attributes) throws IOException  
    {
        // выполнить преобразование типа
        IECPrivateKey ecPrivateKey = (IECPrivateKey)privateKey; 
        
		// закодировать параметры ключа
		AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
			new ObjectIdentifier(keyOID()), Null.INSTANCE
		); 
		// закодировать значение личного ключа
		byte[] encodedD = Convert.fromBigInteger(ecPrivateKey.getS(), Endian.BIG_ENDIAN, 32); 

        // закодировать личный ключ
        aladdin.asn1.kz.ECPrivateKey encodedKey = new aladdin.asn1.kz.ECPrivateKey(
            new Integer(1), new OctetString(encodedD)
        ); 
        // вернуть закодированное представление
        return new PrivateKeyInfo(new Integer(0), 
            algorithm, new OctetString(encodedKey.encoded()), attributes
        ); 
    }
	// раскодировать личный ключ
	@Override public IPrivateKey decodePrivateKey(
        Factory factory, PrivateKeyInfo encoded) throws IOException
    {
        // раскодировать личный ключ
        aladdin.asn1.kz.ECPrivateKey encodedKey = new aladdin.asn1.kz.ECPrivateKey(
            Encodable.decode(encoded.privateKey().value())
        ); 
		// раскодировать значение личного ключа
        BigInteger D = Convert.toBigInteger(encodedKey.value().value(), Endian.BIG_ENDIAN); 

		// создать личный ключ
		return new ECPrivateKey(factory, null, keyOID(), parameters, D); 
    }
}
