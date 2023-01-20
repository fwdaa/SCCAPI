package aladdin.capi.gost.culture;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*;
import aladdin.capi.pbe.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Национальные особенности ГОСТ R34.10-2012 (Magma/Kuznechik + ACPKM)
///////////////////////////////////////////////////////////////////////////
public class GOSTR2012_512_ACPKM extends aladdin.capi.Culture
{
    // конструктор
    public GOSTR2012_512_ACPKM() { this(8); }

    // конструктор
    public GOSTR2012_512_ACPKM(int blockSize) 
            
        // сохранить переданные параметры
        { this.blockSize = blockSize; } private final int blockSize; 

    // параметры алгоритмов
    @Override public AlgorithmIdentifier hashAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_2012_512), Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier cipherAlgorithm(IRand rand) throws IOException 
    { 
        if (blockSize == 8)
        { 
            // сгенерировать синхропосылку 
		    byte[] iv = new byte[12]; rand.generate(iv, 0, iv.length); 

            // вернуть параметры алгоритма
            return new AlgorithmIdentifier(
                new ObjectIdentifier(OID.GOSTR3412_64_CTR_ACPKM),
                new GOSTR3412EncryptionParameters(new OctetString(iv))
            ); 
        }
        else { 
		    // сгенерировать синхропосылку 
		    byte[] iv = new byte[16]; rand.generate(iv, 0, iv.length); 

            // вернуть параметры алгоритма
            return new AlgorithmIdentifier(
                new ObjectIdentifier(OID.GOSTR3412_128_CTR_ACPKM),
                new GOSTR3412EncryptionParameters(new OctetString(iv))
            ); 
        }
    }
	@Override public AlgorithmIdentifier signHashAlgorithm(IRand rand)
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3410_2012_512), Null.INSTANCE
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_2012_R3410_2012_512), null
        ); 
    }
	@Override public AlgorithmIdentifier transportKeyAlgorithm(IRand rand)
    { 
        // указать идентификатор алгоритма
        String oid = (blockSize == 8) ? OID.GOSTR3412_64_WRAP_KEXP15 : 
            OID.GOSTR3412_128_WRAP_KEXP15; 

        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(new ObjectIdentifier(oid),
            new GOSTR3410KEGParameters(new ObjectIdentifier(OID.GOSTR3410_2012_DH_512))
        ); 
    }
    @Override public AlgorithmIdentifier transportAgreementAlgorithm(IRand rand) 
    { 
        // указать идентификатор алгоритма
        String oid = (blockSize == 8) ? OID.GOSTR3412_64_WRAP_KEXP15 : 
            OID.GOSTR3412_128_WRAP_KEXP15; 

        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(new ObjectIdentifier(oid),
            new GOSTR3410KEGParameters(new ObjectIdentifier(OID.GOSTR3410_2012_DH_512))
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Парольная защита
    ///////////////////////////////////////////////////////////////////////////
    public class PKCS12 extends PBEDefaultCulture
    {
        // конструктор
        public PKCS12(PBEParameters parameters) 
        {         
            // сохранить переданные параметры
            super(new GOSTR2012_512_ACPKM(), parameters, true); 
        } 
    }
}
