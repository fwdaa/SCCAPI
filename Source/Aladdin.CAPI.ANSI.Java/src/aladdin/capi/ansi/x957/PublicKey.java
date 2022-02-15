package aladdin.capi.ansi.x957;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма DSA
///////////////////////////////////////////////////////////////////////////
public class PublicKey extends aladdin.capi.PublicKey implements IPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = -4595600085508250456L;
    
    // параметры ключа
    private final IParameters parameters; private final BigInteger y;
    
    // конструктор
	public PublicKey(aladdin.capi.KeyFactory keyFactory, IParameters parameters, BigInteger y) 
    {
        // сохранить переданные параметры
        super(keyFactory); this.parameters = parameters; this.y = y; 
    }
    // параметры ключа
	@Override public final IParameters parameters () { return parameters; }
    // параметры ключа
	@Override public final IParameters getParams() { return parameters; }
    // значение открытого ключа
    @Override public final BigInteger getY() { return y; }
}
