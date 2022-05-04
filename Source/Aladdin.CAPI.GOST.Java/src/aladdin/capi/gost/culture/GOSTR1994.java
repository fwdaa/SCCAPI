package aladdin.capi.gost.culture;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*; 
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Национальные особенности ГОСТ R34.10-1994
///////////////////////////////////////////////////////////////////////////
public class GOSTR1994 extends GOST28147
{
    // конструктор
    public GOSTR1994() { this(OID.ENCRYPTS_A); }
    // конструктор
    public GOSTR1994(String encryptionParams) { super(encryptionParams); }
    
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
            new ObjectIdentifier(OID.GOSTR3410_1994), Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_94_R3410_1994), null
        ); 
    }
	@Override public AlgorithmIdentifier transportKeyAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3410_1994), Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier transportAgreementAlgorithm(IRand rand) throws IOException
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3410_1994_ESDH), keyWrapAlgorithm(rand)
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Парольная защита
    ///////////////////////////////////////////////////////////////////////////
    public static class PKCS12 extends PBEDefaultCulture
    {
        // конструктор
        public PKCS12(PBEParameters parameters, String encryptionParams) 
        {         
            // сохранить переданные параметры
            super(new GOSTR1994(encryptionParams), parameters, true); 
        } 
    }
}
