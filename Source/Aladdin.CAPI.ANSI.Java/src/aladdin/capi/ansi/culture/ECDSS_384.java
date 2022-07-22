package aladdin.capi.ansi.culture; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Национальные особенности ECDSS (384 бит)
///////////////////////////////////////////////////////////////////////////
public class ECDSS_384 extends aladdin.capi.Culture
{
    // параметры алгоритмов
    @Override public AlgorithmIdentifier hashAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
            Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier hmacAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_384), 
            Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException 
    { 
        // сгенерировать синхропосылку
	    byte[] iv = new byte[16]; rand.generate(iv, 0, iv.length); 
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_CBC), 
            new OctetString(iv)
        ); 
    }
    @Override public AlgorithmIdentifier keyWrapAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_WRAP), 
            Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier signHashAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), null
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384), null
        ); 
    }
    @Override public AlgorithmIdentifier transportAgreementAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_384), 
            keyWrapAlgorithm(rand)
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Парольная защита
    ///////////////////////////////////////////////////////////////////////////
    public static class PKCS12 extends PBEDefaultCulture
    {
        // конструктор
        public PKCS12(PBEParameters parameters) { super(new ECDSS_384(), parameters, true); } 
    }
}
