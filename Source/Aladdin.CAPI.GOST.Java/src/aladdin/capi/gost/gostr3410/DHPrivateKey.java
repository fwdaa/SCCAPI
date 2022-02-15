package aladdin.capi.gost.gostr3410;
import aladdin.capi.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////////
public class DHPrivateKey extends aladdin.capi.PrivateKey implements IDHPrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 3903126747807109217L;
    
    // параметры ключа и секретное значение
    private final IDHParameters parameters; private final BigInteger x;
    
    // конструктор
	public DHPrivateKey(Factory factory, SecurityObject scope, 
        String keyOID, IDHParameters parameters, BigInteger x) 
	{ 	
        // сохранить переданные параметры
		super(factory, scope, keyOID); this.parameters = parameters; this.x = x; 
    } 
    // параметры ключа
	@Override public final IDHParameters parameters() { return parameters; } 
    // секретное значение
	@Override public final BigInteger getX() { return x; } 
}
