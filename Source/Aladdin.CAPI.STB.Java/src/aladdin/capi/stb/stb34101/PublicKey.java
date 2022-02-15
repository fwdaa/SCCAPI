package aladdin.capi.stb.stb34101;
import java.security.spec.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма СТБ 34.101
///////////////////////////////////////////////////////////////////////////
public class PublicKey extends aladdin.capi.PublicKey implements IPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 4442119396606408504L;

    // параметры ключа
    private final Parameters parameters; private final ECPoint q;
    
    // конструктор
	public PublicKey(aladdin.capi.KeyFactory keyFactory, IParameters parameters, ECPoint q) 
    {
        // сохранить переданные параметры
        super(keyFactory); this.q = q; 
        
        // сохранить пекреданные параметры
        this.parameters = Parameters.convert(parameters); 
    }
    // параметры ключа
	@Override public final Parameters parameters() { return parameters; }
    // параметры ключа
	@Override public final Parameters getParams() { return parameters; }
    // значение открытого ключа
    @Override public final ECPoint getW() { return q; }
}
