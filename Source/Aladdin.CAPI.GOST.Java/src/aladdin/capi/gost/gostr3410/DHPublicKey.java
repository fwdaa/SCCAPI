package aladdin.capi.gost.gostr3410;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////////
public class DHPublicKey extends aladdin.capi.PublicKey implements IDHPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = -2325746400156972004L;

    // параметры ключа
    private final IDHParameters parameters; private final BigInteger y;
    
    // конструктор
	public DHPublicKey(aladdin.capi.KeyFactory keyFactory, IDHParameters parameters, BigInteger y) 
    {
        // сохранить переданные параметры
        super(keyFactory); this.parameters = parameters; this.y = y; 
    }
    // параметры ключа
	@Override public final IDHParameters parameters () { return parameters; }
    // значение открытого ключа
    @Override public final BigInteger getY() { return y; }
}
