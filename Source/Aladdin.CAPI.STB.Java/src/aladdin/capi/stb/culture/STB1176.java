package aladdin.capi.stb.culture;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*; 
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Национальные особенности СТБ 1176 (подпись данных)
///////////////////////////////////////////////////////////////////////////
public class STB1176 extends aladdin.capi.Culture
{
    // конструктор
    public STB1176(String sboxParams) 
        
        // сохранить переданные параметры
        { this.sboxParams = sboxParams; } private final String sboxParams; 
        
    // конструктор
    public STB1176() { this(OID.GOST28147_SBLOCK_1); } 
    
    // параметры алгоритмов
    @Override public AlgorithmIdentifier hashAlgorithm(IRand rand) throws IOException
    { 
        // сгенерировать стартовое значение
        byte[] start = new byte[32]; rand.generate(start, 0, start.length); 
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB11761_HASH), new OctetString(start)
        ); 
    }
    @Override public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException
    { 
        // сгенерировать синхропосылку
        byte[] iv = new byte[8]; rand.generate(iv, 0, iv.length); 
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOST28147_CFB), 
            new GOSTParams(new OctetString(iv), new ObjectIdentifier(sboxParams))
        ); 
    }
    @Override public AlgorithmIdentifier keyWrapAlgorithm(IRand rand) throws IOException
    { 
        // сгенерировать синхропосылку
        byte[] iv = new byte[8]; rand.generate(iv, 0, iv.length); 
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOST28147_CFB), 
            new GOSTParams(new OctetString(iv), new ObjectIdentifier(sboxParams))
        ); 
    }
    // параметры алгоритма подписи хэш-значения
	@Override public AlgorithmIdentifier signHashAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB11762_SIGN), null
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB11762_SIGN), null
        ); 
    }
	@Override public AlgorithmIdentifier transportKeyAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB11762_BDH_KEYTRANS), Null.INSTANCE
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
            super(parameters); culture = new STB1176(sboxParams); 
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

