package aladdin.capi.gost.culture;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*; 
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Национальные особенности ГОСТ R34.10-2001
///////////////////////////////////////////////////////////////////////////
public class GOSTR2001 extends GOST28147
{
    // конструктор
    public GOSTR2001(String encryptionParams) { super(encryptionParams); }
    
    // параметры алгоритмов
    @Override public AlgorithmIdentifier hashAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_94), Null.INSTANCE
        ); 
    }
	@Override public AlgorithmIdentifier signHashAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3410_2001), Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_94_R3410_2001), null
        ); 
    }
	@Override public AlgorithmIdentifier transportKeyAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3410_2001), Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier transportAgreementAlgorithm(IRand rand) throws IOException 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3410_2001_ESDH), keyWrapAlgorithm(rand)
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Парольная защита
    ///////////////////////////////////////////////////////////////////////////
    public static class PKCS12 extends PBECulture.Default
    {
        // конструктор
        public PKCS12(String encryptionParams, PBEParameters parameters) 
        {         
            // сохранить переданные параметры
            super(new GOSTR2001(encryptionParams), parameters, true); 
        } 
    }
}
