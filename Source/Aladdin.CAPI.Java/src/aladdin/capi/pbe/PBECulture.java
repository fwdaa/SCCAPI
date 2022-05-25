package aladdin.capi.pbe;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.*;
import aladdin.asn1.iso.pkcs.pkcs5.*;
import aladdin.asn1.iso.pkcs.pkcs7.*;
import aladdin.capi.*;
import java.io.*;
import java.security.*;

///////////////////////////////////////////////////////////////////////////
// Парольная защита
///////////////////////////////////////////////////////////////////////////
public abstract class PBECulture implements IPBECultureFactory
{
    // параметры шифрования по паролю
    private final PBEParameters pbeParameters; 

    // конструктор
    public PBECulture(PBEParameters pbeParameters)
    { 
        // сохранить переданные параметры
        this.pbeParameters = pbeParameters; 
    } 
    // параметры парольной защиты
    @Override public PBECulture getPBECulture(Object window, String keyOID) { return this; }
    
    // параметры шифрования по паролю 
    public final PBEParameters pbeParameters() { return pbeParameters; } 

    // параметры алгоритма хэширования
    public abstract AlgorithmIdentifier hashAlgorithm(IRand rand) throws IOException; 
    
    // параметры алгоритма HMAC
    public AlgorithmIdentifier hmacAlgorithm(IRand rand) throws IOException { return null; }
    
    // параметры алгоритма шифрования по паролю
    public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException { return null; } 
    
    // параметры алгоритма наследования ключа
    protected AlgorithmIdentifier kdfAlgorithm(IRand rand)	throws IOException
    { 
    	// получить параметры HMAC
		AlgorithmIdentifier hmacParameters = hmacAlgorithm(rand); 

        // проверить наличие параметров
		if (hmacParameters == null) throw new UnsupportedOperationException(); 

        // определить число итераций
        int iterations = pbeParameters().pbeIterations(); 

        // выделить память для salt-значения
        byte[] salt = new byte[pbeParameters().pbeSaltLength()]; 

        // сгенерировать salt-значение
        rand.generate(salt, 0, salt.length); 

        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs5.OID.PBKDF2), 
            new PBKDF2Parameter(new OctetString(salt), 
                new aladdin.asn1.Integer(iterations), null, hmacParameters
            )
        ); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Зашифровать данные по паролю
    ///////////////////////////////////////////////////////////////////////
    public ContentInfo passwordEncryptData( 
        Factory factory, SecurityStore scope, IRand rand, 
        ISecretKey password, CMSData data, Attributes attributes) 
        throws IOException, InvalidKeyException
    {
        // получить параметры алгоритма шифрования
        AlgorithmIdentifier passwordAlgorithm = cipherAlgorithm(rand); 

        // проверить наличие алгоритма 
        if (passwordAlgorithm == null) throw new UnsupportedOperationException(); 
        
        // зашифровать данные по паролю
        EncryptedData encryptedData = CMS.encryptData(
            factory, scope, password, passwordAlgorithm, data, attributes
        ); 
        // вернуть закодированную структуру
        return new ContentInfo(new ObjectIdentifier(
            aladdin.asn1.iso.pkcs.pkcs7.OID.ENCRYPTED_DATA), encryptedData
        );
    }
}
