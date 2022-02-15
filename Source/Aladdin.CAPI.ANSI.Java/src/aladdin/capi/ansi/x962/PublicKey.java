package aladdin.capi.ansi.x962;
import java.security.spec.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма 
///////////////////////////////////////////////////////////////////////////
public class PublicKey extends aladdin.capi.PublicKey implements IPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 7093557779672302837L;

    // параметры ключа
    private final Parameters parameters; private final ECPoint q;
    
    // конструктор
	public PublicKey(aladdin.capi.KeyFactory keyFactory, 
        IParameters parameters, ECPoint q) 
    {
        // сохранить переданные параметры
        super(keyFactory); this.q = q; 
        
        // сохранить переданные параметры
        this.parameters = Parameters.convert(parameters); 
    }
    // параметры ключа
	@Override public final Parameters parameters() { return parameters; }
    // параметры ключа
	@Override public final Parameters getParams() { return parameters; }
    // точка эллиптической кривой
	@Override public final ECPoint getW() { return q; } 
}
