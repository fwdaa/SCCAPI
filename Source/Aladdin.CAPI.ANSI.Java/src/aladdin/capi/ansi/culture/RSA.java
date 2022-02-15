package aladdin.capi.ansi.culture; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Национальные особенности RSA
///////////////////////////////////////////////////////////////////////////
public class RSA extends aladdin.capi.Culture
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
    @Override public AlgorithmIdentifier ciphermentAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), 
            Null.INSTANCE
        ); 
    }
    // параметры алгоритма подписи хэш-значения
	@Override public AlgorithmIdentifier signHashAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1), null
        ); 
    }
	@Override public AlgorithmIdentifier transportKeyAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return ciphermentAlgorithm(rand); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Парольная защита
    ///////////////////////////////////////////////////////////////////////////
    public static class PKCS12 extends PBECulture
    {
        // национальные особенности
        private final aladdin.capi.Culture culture; 

        // конструктор
        public PKCS12(PBEParameters parameters) 
        {         
            // сохранить переданные параметры
            super(parameters); culture = new RSA(); 
        } 
        // национальные особенности
        @Override protected aladdin.capi.Culture baseCulture() { return culture; } 
        
        // параметры алгоритмов
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
