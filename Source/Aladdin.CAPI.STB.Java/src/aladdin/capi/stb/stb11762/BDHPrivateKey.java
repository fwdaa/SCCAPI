package aladdin.capi.stb.stb11762;
import aladdin.capi.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDHPrivateKey extends aladdin.capi.PrivateKey implements IBDHPrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 5316251136938809592L;
    
    // параметры ключа и секретное значение
    private final IBDHParameters parameters; private final BigInteger x;
    
    // конструктор
	public BDHPrivateKey(Factory factory, SecurityObject scope, 
        String keyOID, IBDHParameters parameters, BigInteger x) 
	{ 	
        // сохранить переданные параметры
		super(factory, scope, keyOID); this.parameters = parameters; this.x = x; 
    } 
    // параметры ключа
	@Override public final IBDHParameters parameters() { return parameters; } 
    // секретное значение
	@Override public final BigInteger bdhX() { return x; } 
}
