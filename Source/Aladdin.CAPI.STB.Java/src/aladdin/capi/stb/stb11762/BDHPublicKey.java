package aladdin.capi.stb.stb11762;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDHPublicKey extends aladdin.capi.PublicKey implements IBDHPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 2602886075581544088L;

    // параметры ключа
    private final IBDHParameters parameters; private final BigInteger y;
    
    // конструктор
	public BDHPublicKey(aladdin.capi.KeyFactory keyFactory, IBDHParameters parameters, BigInteger y) 
    {
        // сохранить переданные параметры
        super(keyFactory); this.parameters = parameters; this.y = y; 
    }
    // параметры ключа
	@Override public final IBDHParameters parameters() { return parameters; }
    // значение открытого ключа
    @Override public final BigInteger bdhY() { return y; }
}
