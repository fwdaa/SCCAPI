package aladdin.capi.ansi.culture; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*;
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Национальные особенности DSS
///////////////////////////////////////////////////////////////////////////
public class DSS extends aladdin.capi.Culture
{
    // параметры алгоритмов
    @Override public AlgorithmIdentifier hashAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
            Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier hmacAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_HMAC_SHA1),
            Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException
    { 
	    // сгенерировать синхропосылку
	    byte[] iv = new byte[8]; rand.generate(iv, 0, iv.length); 
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_TDES192_CBC), 
            new OctetString(iv)
        ); 
    }
    @Override public AlgorithmIdentifier keyWrapAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_TDES192_WRAP), 
            Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier signHashAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA_SHA1), null
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA_SHA1), null
        ); 
    }
    @Override public AlgorithmIdentifier transportAgreementAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_ESDH), 
            keyWrapAlgorithm(rand)
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Парольная защита
    ///////////////////////////////////////////////////////////////////////////
    public static class PKCS12 extends PBECulture
    {
        // конструктор
        public PKCS12(PBEParameters parameters) { super(parameters); } 
        
        // параметры алгоритма хэширования
        @Override public AlgorithmIdentifier hashAlgorithm(IRand rand) throws IOException
        {
            // параметры алгоритма хэширования
            return new DSS().hashAlgorithm(rand); 
        }
        @Override public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException	
        { 
            // определить число итераций
            int iterations = pbeParameters().pbeIterations(); 
            
            // выделить буфер для случайных данных
            byte[] salt = new byte[pbeParameters().pbeSaltLength()]; 
                
            // сгенерировать случайные данные
            rand.generate(salt, 0, salt.length); 

            // вернуть параметры алгоритма
            return new AlgorithmIdentifier(
                new ObjectIdentifier(
                    aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_TDES_192_CBC), 
                new aladdin.asn1.iso.pkcs.pkcs5.PBEParameter(
                    new OctetString(salt), new Integer(iterations)
                )
            ); 
        } 
    }
}
