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
// Парольная защита по умолчанию
///////////////////////////////////////////////////////////////////////////
public class PBEDefaultCulture extends PBECulture
{
    // криптографическая культура
    private final aladdin.capi.Culture culture; private final boolean usePBE; 
        
    // конструктор
    public PBEDefaultCulture(Culture culture, PBEParameters pbeParameters, boolean usePBE)
    { 
        // сохранить переданные параметры
        super(pbeParameters); this.culture = culture; this.usePBE = usePBE; 
    } 
    // криптографическая культура
    protected final aladdin.capi.Culture baseCulture() { return culture; }

    // параметры алгоритма хэширования
    @Override public AlgorithmIdentifier hashAlgorithm(IRand rand) throws IOException
    {
        // вернуть параметры алгоритма
        return culture.hashAlgorithm(rand); 
    }
    // параметры алгоритма HMAC
    @Override public AlgorithmIdentifier hmacAlgorithm(IRand rand) throws IOException
    {
        // вернуть параметры алгоритма
        return culture.hmacAlgorithm(rand); 
    }
    // параметры алгоритма шифрования по паролю
    @Override public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException	
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
    ///////////////////////////////////////////////////////////////////////
    // Зашифровать данные по паролю
    ///////////////////////////////////////////////////////////////////////
    @Override public ContentInfo passwordEncryptData( 
        Factory factory, SecurityStore scope, IRand rand, 
        ISecretKey password, CMSData data, Attributes attributes) 
        throws IOException, InvalidKeyException
    {
        // зашифровать данные по паролю
        if (usePBE) return super.passwordEncryptData(factory, scope, rand, password, data, attributes); 

        // получить параметры алгоритма наследования ключа
        AlgorithmIdentifier[] keyDeriveAlgorithms = new AlgorithmIdentifier[] { kdfAlgorithm(rand) }; 

        // получить параметры алгоритма шифрования
        AlgorithmIdentifier cipherAlgorithm = baseCulture().cipherAlgorithm(rand);
                
        // проверить указание алгоритма
        if (cipherAlgorithm == null) throw new UnsupportedOperationException();  

        // получить алгоритм шифрования ключа
        AlgorithmIdentifier keyWrapAlgorithm = baseCulture().keyWrapAlgorithm(rand);
                
        // проверить указание параметров
        if (keyWrapAlgorithm == null) throw new UnsupportedOperationException();  

        // получить параметры алгоритма шифрования ключа
        AlgorithmIdentifier[] keyWrapAlgorithms = new AlgorithmIdentifier[] { keyWrapAlgorithm }; 
                
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
