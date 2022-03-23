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
    public static class PKCS12 extends PBECulture.Default
    {
        // конструктор
        public PKCS12(String sboxParams, PBEParameters parameters) 
        {         
            // сохранить переданные параметры
            super(new STB1176Pro(sboxParams), parameters, true); 
        } 
    }
}
