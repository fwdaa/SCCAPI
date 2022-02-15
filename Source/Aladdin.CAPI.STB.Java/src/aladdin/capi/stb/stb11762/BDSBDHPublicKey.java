package aladdin.capi.stb.stb11762;
import java.math.*; 

///////////////////////////////////////////////////////////////////////
// Открытый ключ подписи и обмена
///////////////////////////////////////////////////////////////////////
public class BDSBDHPublicKey extends aladdin.capi.PublicKey implements IBDSBDHPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = -4102993374421267783L;

    // параметры ключа
    private final IBDSBDHParameters parameters; 
    // открытый ключ подписи и обмена
	private final BigInteger bdsY; private final BigInteger bdhY;	
    
    // конструктор
	public BDSBDHPublicKey(aladdin.capi.KeyFactory keyFactory, 
        IBDSBDHParameters parameters, BigInteger bdsY, BigInteger bdhY) 
    {
        // сохранить переданные параметры
        super(keyFactory); this.parameters = parameters; this.bdsY = bdsY; this.bdhY = bdhY;
    }
    // параметры ключа
	@Override public final IBDSBDHParameters parameters () { return parameters; }
    // параметры ключа
	@Override public final IBDSBDHParameters getParams() { return parameters; }
    // значение открытого ключа
    @Override public final BigInteger bdsY() { return bdsY; }
    @Override public final BigInteger getY() { return bdsY; }
    // значение открытого ключа
    @Override public final BigInteger bdhY() { return bdhY; }
}
