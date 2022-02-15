package aladdin.capi.stb.culture;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*; 
import aladdin.capi.*;
import aladdin.capi.pbe.*;

///////////////////////////////////////////////////////////////////////////
// Национальные особенности СТБ 1176 (подпись хэш-значения)
///////////////////////////////////////////////////////////////////////////
public class STB1176Pro extends STB1176
{
    // конструктор
    public STB1176Pro(String sboxParams) { super(sboxParams); }
    // конструктор
    public STB1176Pro() { super(); } 
    
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB11762_PRE_SIGN), Null.INSTANCE
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
        public PKCS12(String sboxParams, PBEParameters parameters) 
        {         
            // сохранить переданные параметры
            super(parameters); culture = new STB1176Pro(sboxParams); 
        } 
        // национальные особенности
        @Override protected aladdin.capi.Culture baseCulture() { return culture; } 
        
        // параметры алгоритмов
        @Override public AlgorithmIdentifier hmacAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new AlgorithmIdentifier(
                new ObjectIdentifier(OID.STB34101_HMAC_HSPEC), 
                new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB11761_HASH), 
                    Null.INSTANCE
                )
            ); 
        }
    }
}
