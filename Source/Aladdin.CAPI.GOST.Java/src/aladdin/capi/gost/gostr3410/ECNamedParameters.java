package aladdin.capi.gost.gostr3410;
import aladdin.asn1.gost.*; 

///////////////////////////////////////////////////////////////////////////
// Именованные параметры ГОСТ Р34.10
///////////////////////////////////////////////////////////////////////////
public class ECNamedParameters extends ECParameters implements INamedParameters
{
    private static final long serialVersionUID = 4582095259741869115L;
    
    // создать параметры
    public static ECNamedParameters create(String paramOID, String hashOID, String sboxOID)
    {
        // при указании идентификатора таблицы пдстановок для хэширования
        if (hashOID.startsWith(OID.HASHES))
        {
            // создать параметры ключа ГОСТ Р34.10-2001
            return new ECNamedParameters2001(paramOID, hashOID, sboxOID); 
        }
        // создать параметры ключа ГОСТ Р34.10-2012
        else return new ECNamedParameters2012(paramOID, hashOID); 
    }
    // конструктор
    public ECNamedParameters(String paramOID, String hashOID, String sboxOID) 
    {
        // сохранить переданные параметры
        super(GOSTR3410ParamSet.parameters(paramOID)); 
        
        // сохранить переданные параметры
        this.paramOID = paramOID; this.hashOID = hashOID; this.sboxOID = sboxOID; 
    }
	@Override public final String paramOID() { return paramOID; } private final String paramOID;
	@Override public final String hashOID () { return  hashOID; } private final String hashOID;
	@Override public final String sboxOID () { return  sboxOID; } private final String sboxOID;
}
