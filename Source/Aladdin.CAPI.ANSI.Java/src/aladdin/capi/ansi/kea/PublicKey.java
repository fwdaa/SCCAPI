package aladdin.capi.ansi.kea;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма KEA
///////////////////////////////////////////////////////////////////////////
public class PublicKey extends aladdin.capi.PublicKey implements IPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 1348377048145565663L;

    // параметры ключа
    private final IParameters parameters; private final BigInteger y;
    
    // конструктор
	public PublicKey(aladdin.capi.KeyFactory keyFactory, IParameters parameters, BigInteger y) 
    {
        // сохранить переданные параметры
        super(keyFactory); this.parameters = parameters; this.y = y; 
    }
    // параметры ключа
	@Override public final IParameters parameters() { return parameters; }
    // значение открытого ключа
    @Override public final BigInteger getY() { return y; }
}
