package aladdin.capi.ansi.x957;
import aladdin.capi.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма DSA
///////////////////////////////////////////////////////////////////////////
public class PrivateKey extends aladdin.capi.PrivateKey implements IPrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = -7442466698309471853L;
    
    // параметры ключа и секретное значение
    private final IParameters parameters; private final BigInteger x;
    
    // конструктор
	public PrivateKey(Factory factory, SecurityObject scope, 
        String keyOID, IParameters parameters, BigInteger x) 
	{ 	
        // сохранить переданные параметры
		super(factory, scope, keyOID); this.parameters = parameters; this.x = x; 
    } 
    // параметры ключа
	@Override public final IParameters parameters() { return parameters; } 
    // секретное значение
	@Override public final BigInteger getX() { return x; } 
}