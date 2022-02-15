package aladdin.capi.kz.culture;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.kz.*; 
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Национальные особенности ГОСТ
///////////////////////////////////////////////////////////////////////////
public class GOST2004 extends aladdin.capi.Culture
{
    // параметры алгоритмов
    @Override public AlgorithmIdentifier hashAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_GOST34310_34311_2004_T), Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException
    { 
        // сгенерировать синхропосылку
        byte[] iv = new byte[8]; rand.generate(iv, 0, iv.length); 
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_CIPHER_GOST), new OctetString(iv)
        ); 
    }
    @Override public AlgorithmIdentifier keyWrapAlgorithm(IRand rand) throws IOException
    { 
        // сгенерировать синхропосылку
        byte[] iv = new byte[8]; rand.generate(iv, 0, iv.length); 
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_CIPHER_GOST), new OctetString(iv)
        ); 
    }
    // параметры алгоритм подписи хэш-значения
	@Override public AlgorithmIdentifier signHashAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_GOST34310_2004), Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_GOST34310_34311_2004_T), null
        ); 
    }
    @Override public AlgorithmIdentifier transportAgreementAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_GOST28147), Null.INSTANCE
        ); 
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
            super(parameters); culture = new GOST2004(); 
        } 
        // национальные особенности
        @Override protected aladdin.capi.Culture baseCulture() { return culture; } 
        
        // параметры алгоритмов
        @Override public AlgorithmIdentifier hmacAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new AlgorithmIdentifier(
                new ObjectIdentifier(OID.GAMMA_HMAC_GOST34311_95_T), 
                Null.INSTANCE
            ); 
        }
    }
}
