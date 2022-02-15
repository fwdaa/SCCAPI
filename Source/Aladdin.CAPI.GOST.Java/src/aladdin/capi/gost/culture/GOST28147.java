package aladdin.capi.gost.culture;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*; 
import aladdin.capi.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Национальные особенности
///////////////////////////////////////////////////////////////////////////
public abstract class GOST28147 extends aladdin.capi.Culture
{
    // идентификатор набора шифрования
    private final String encryptionParams; 
    
    // конструктор
    public GOST28147(String encryptionParams) 
    {     
        // сохранить переданные параметры
        this.encryptionParams = encryptionParams; 
    } 
    // идентификатор набора параметров шифрования
    protected String encryptionParams() { return encryptionParams; }

    @Override public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException 
    { 
        // сгенерировать синхропосылку
	    byte[] iv = new byte[8]; rand.generate(iv, 0, iv.length); 
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOST28147_89), 
            new GOST28147CipherParameters(
                new OctetString(iv), new ObjectIdentifier(encryptionParams)
            )
        ); 
    }
    @Override public AlgorithmIdentifier keyWrapAlgorithm(IRand rand) throws IOException 
    { 
	    // сгенерировать случайные данные
	    byte[] ukm = new byte[8]; rand.generate(ukm, 0, ukm.length); 
        
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
            new KeyWrapParameters(
			    new ObjectIdentifier(encryptionParams), new OctetString(ukm)
		    )
        ); 
    }
}
