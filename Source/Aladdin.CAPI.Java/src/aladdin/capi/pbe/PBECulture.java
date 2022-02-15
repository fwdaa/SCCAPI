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
public abstract class PBECulture
{
    // параметры шифрования по паролю
    private final PBEParameters pbeParameters; 

    // конструктор
    public PBECulture(PBEParameters pbeParameters)
    { 
        // сохранить переданные параметры
        this.pbeParameters = pbeParameters; 
    } 
    // национальные особенности
    protected aladdin.capi.Culture baseCulture() { return null; }

    // параметры шифрования по паролю 
    public PBEParameters pbeParameters() { return pbeParameters; } 

    // параметры алгоритмов
    public AlgorithmIdentifier hashAlgorithm(IRand rand) throws IOException
    { 
        // вернуть параметры алгоритма
        return baseCulture().hashAlgorithm(rand); 
    }
    public abstract AlgorithmIdentifier hmacAlgorithm(IRand rand) throws IOException; 
        
    public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException	
    { 
        // закодировать параметры шифрования
        AlgorithmIdentifier cipherAlgorithm = baseCulture().cipherAlgorithm(rand); 
        
        // проверить указание алгоритма
        if (cipherAlgorithm == null) return null;  
            
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs5.OID.PBES2), 
            new PBES2Parameter(kdfAlgorithm(rand), cipherAlgorithm)
        ); 
    } 
    public AlgorithmIdentifier kdfAlgorithm(IRand rand)	throws IOException
    { 
        // определить число итераций
        int iterations = pbeParameters.pbeIterations(); 
            
        // выделить память для salt-значения
        byte[] salt = new byte[pbeParameters.pbeSaltLength()]; 

        // сгенерировать salt-значение
        rand.generate(salt, 0, salt.length); 

        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs5.OID.PBKDF2), 
            new PBKDF2Parameter(new OctetString(salt), 
                new aladdin.asn1.Integer(iterations), null, hmacAlgorithm(rand)
            )
        ); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Зашифровать данные по паролю
    ///////////////////////////////////////////////////////////////////////
    public ContentInfo passwordEncryptData( 
        Factory factory, SecurityStore scope, IRand rand, boolean useCipherPBE, 
        ISecretKey password, CMSData data, Attributes attributes) 
        throws IOException, InvalidKeyException
    {
        // получить параметры алгоритма шифрования
        AlgorithmIdentifier passwordAlgorithm = cipherAlgorithm(rand); 

        // при использовании алгоритма шифрования по паролю
        if (useCipherPBE && passwordAlgorithm != null)
        {
            // зашифровать данные по паролю
            EncryptedData encryptedData = CMS.encryptData(
                factory, scope, password, passwordAlgorithm, data, attributes
            ); 
            // вернуть закодированную структуру
            return new ContentInfo(new ObjectIdentifier(
                aladdin.asn1.iso.pkcs.pkcs7.OID.ENCRYPTED_DATA), encryptedData
            );
        }
        else {
            // получить параметры алгоритма наследования ключа
            AlgorithmIdentifier[] keyDeriveAlgorithms = 
                new AlgorithmIdentifier[] { kdfAlgorithm(rand) }; 

            // получить параметры алгоритма шифрования
            AlgorithmIdentifier cipherAlgorithm = baseCulture().cipherAlgorithm(rand);
                
            // проверить указание алгоритма
            if (cipherAlgorithm == null) throw new UnsupportedOperationException();  

            // получить алгоритм шифрования ключа
			AlgorithmIdentifier keyWrapAlgorithm = baseCulture().keyWrapAlgorithm(rand);
                
            // проверить указание параметров
            if (keyWrapAlgorithm == null) throw new UnsupportedOperationException();  

            // получить параметры алгоритма шифрования ключа
            AlgorithmIdentifier[] keyWrapAlgorithms = 
                new AlgorithmIdentifier[] { keyWrapAlgorithm }; 
                
            // зашифровать данные
            EnvelopedData envelopedData = CMS.passwordEncryptData(
                factory, scope, rand, new ISecretKey[] { password }, cipherAlgorithm, 
                keyDeriveAlgorithms, keyWrapAlgorithms, data, attributes
            ); 
            // вернуть закодированную структуру
            return new ContentInfo(new ObjectIdentifier(
                aladdin.asn1.iso.pkcs.pkcs7.OID.ENVELOPED_DATA), envelopedData
            ); 
        }
    }
}
