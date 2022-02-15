package aladdin.capi.stb.stb11762;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDSPublicKey extends aladdin.capi.PublicKey implements IBDSPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 7202058754350150152L;

    // параметры ключа
    private final IBDSParameters parameters; private final BigInteger y;
    
    // конструктор
	public BDSPublicKey(aladdin.capi.KeyFactory keyFactory, IBDSParameters parameters, BigInteger y) 
    {
        // сохранить переданные параметры
        super(keyFactory); this.parameters = parameters; this.y = y; 
    }
    // параметры ключа
	@Override public final IBDSParameters parameters() { return parameters; }
    // параметры ключа
	@Override public final IBDSParameters getParams() { return parameters; }
    // значение открытого ключа
    @Override public final BigInteger bdsY() { return y; }
    @Override public final BigInteger getY() { return y; }
}
