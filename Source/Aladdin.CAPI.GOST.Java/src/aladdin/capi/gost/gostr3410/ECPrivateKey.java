package aladdin.capi.gost.gostr3410;
import aladdin.capi.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма ГОСТ Р 34.10-2001,2012
///////////////////////////////////////////////////////////////////////////
public class ECPrivateKey extends aladdin.capi.PrivateKey implements IECPrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 346029498994696039L;
    
    // параметры ключа и секретное значение
    private final ECParameters parameters; private final BigInteger d;
    
    // конструктор
	public ECPrivateKey(Factory factory, SecurityObject scope, 
        String keyOID, IECParameters parameters, BigInteger d) 
	{ 	
        // сохранить переданные параметры
		super(factory, scope, keyOID); this.d = d; 
        
        // сохранить переданные параметры
        this.parameters = ECParameters.convert(parameters);
    } 
    // параметры ключа
	@Override public final IECParameters parameters() { return parameters; } 
    // секретное значение
	@Override public final BigInteger getS() { return d; } 
}
