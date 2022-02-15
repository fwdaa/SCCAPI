package aladdin.capi.stb.culture;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*; 
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Национальные особенности STB34101 (384 бит)
///////////////////////////////////////////////////////////////////////////
public class STB34101_384 extends STB34101
{
    @Override public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException
    { 
		// сгенерировать синхропосылку
		byte[] iv = new byte[16]; rand.generate(iv, 0, iv.length);
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BELT_CFB_192), new OctetString(iv)
        ); 
    }
    @Override public AlgorithmIdentifier keyWrapAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BELT_KEYWRAP_192), Null.INSTANCE
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Парольная защита
    ///////////////////////////////////////////////////////////////////////////
    public static class PKCS12 extends STB34101.PKCS12
    {
        // национальные особенности
        private final aladdin.capi.Culture culture; 

        // конструктор
        public PKCS12(PBEParameters parameters) 
        {         
            // сохранить переданные параметры
            super(parameters); culture = new STB34101_384(); 
        } 
        // национальные особенности
        @Override protected aladdin.capi.Culture baseCulture() { return culture; } 
    }
}
