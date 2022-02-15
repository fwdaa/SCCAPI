package aladdin.capi.stb.culture;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*; 
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 

///////////////////////////////////////////////////////////////////////////
// Национальные особенности STB34101
///////////////////////////////////////////////////////////////////////////
public abstract class STB34101 extends aladdin.capi.Culture
{
    // параметры алгоритмов
    @Override public AlgorithmIdentifier hashAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BELT_HASH), Null.INSTANCE
        ); 
    }
    // параметры алгоритма подписи
	@Override public AlgorithmIdentifier signHashAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BIGN_HBELT), null
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BIGN_HBELT), null
        ); 
    }
	@Override public AlgorithmIdentifier transportKeyAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BIGN_KEYTRANSPORT), Null.INSTANCE
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Парольная защита
    ///////////////////////////////////////////////////////////////////////////
    public static class PKCS12 extends PBECulture
    {
        // конструктор
        public PKCS12(PBEParameters parameters) { super(parameters); }
        
        // параметры алгоритмов
        @Override public AlgorithmIdentifier hmacAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new AlgorithmIdentifier(
                new ObjectIdentifier(OID.STB34101_HMAC_HBELT), 
                Null.INSTANCE
            ); 
        }
    }
}
