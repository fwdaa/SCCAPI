package aladdin.capi.stb.stb11762;
import aladdin.capi.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDSPrivateKey extends aladdin.capi.PrivateKey implements IBDSPrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = -3992891563963029640L;
    
    // параметры ключа и секретное значение
    private final IBDSParameters parameters; private final BigInteger x;
    
    // конструктор
	public BDSPrivateKey(Factory factory, SecurityObject scope, 
        String keyOID, IBDSParameters parameters, BigInteger x) 
	{ 	
        // сохранить переданные параметры
		super(factory, scope, keyOID); this.parameters = parameters; this.x = x; 
    } 
    // параметры ключа
	@Override public final IBDSParameters parameters() { return parameters; } 
    // секретное значение
	@Override public final BigInteger bdsX() { return x; } 
}
