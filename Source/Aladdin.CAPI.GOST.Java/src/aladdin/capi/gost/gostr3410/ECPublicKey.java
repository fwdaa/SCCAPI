package aladdin.capi.gost.gostr3410;
import java.security.spec.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма ГОСТ Р 34.10-2001,2012
///////////////////////////////////////////////////////////////////////////
public class ECPublicKey extends aladdin.capi.PublicKey implements IECPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = -1134147618530131618L;

    // параметры ключа
    private final ECParameters parameters; private final ECPoint q;
    
    // конструктор
	public ECPublicKey(aladdin.capi.KeyFactory keyFactory, IECParameters parameters, ECPoint q) 
    {
        // сохранить переданные параметры
        super(keyFactory); this.q = q; 
        
        // сохранить переданные параметры
        this.parameters = ECParameters.convert(parameters); 
    }
    // параметры ключа
	@Override public final ECParameters parameters() { return parameters; }
    // параметры ключа
	@Override public final ECParameters getParams() { return parameters; }
    // значение открытого ключа
    @Override public final ECPoint getW() { return q; }
}
