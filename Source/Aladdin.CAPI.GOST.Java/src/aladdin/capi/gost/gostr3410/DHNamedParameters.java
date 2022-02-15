package aladdin.capi.gost.gostr3410;
import aladdin.asn1.gost.*; 

///////////////////////////////////////////////////////////////////////////
// Именованные параметры ГОСТ Р34.10-1994
///////////////////////////////////////////////////////////////////////////
public class DHNamedParameters extends DHParameters implements INamedParameters
{
    // выполнить преобразование типа
    public static DHNamedParameters convert(INamedParameters parameters)
    {
        // проверить тип объекта
        if (parameters instanceof DHNamedParameters) return (DHNamedParameters)parameters;
        
        // выполнить преобразование типа
        return new DHNamedParameters(parameters.paramOID(), parameters.hashOID(), parameters.sboxOID()); 
    }
    // конструктор
    public DHNamedParameters(String paramOID, String hashOID, String sboxOID) 
    {
        // сохранить переданные параметры
        super(GOSTR3410ParamSet1994.parameters(paramOID)); 
        
        // сохранить переданные параметры
        this.paramOID = paramOID; this.hashOID = hashOID; this.sboxOID = sboxOID; 
    }
    // конструктор
    public DHNamedParameters(GOSTR3410PublicKeyParameters2001 parameters) 
    {
        // сохранить переданные параметры
        this(parameters.publicKeyParamSet ().value(), 
             parameters.digestParamSet    ().value(), 
             parameters.encryptionParamSet().value()
        ); 
    }
	@Override public final String paramOID() { return paramOID; } private final String paramOID;
	@Override public final String hashOID () { return  hashOID; } private final String hashOID;
	@Override public final String sboxOID () { return  sboxOID; } private final String sboxOID;
}
