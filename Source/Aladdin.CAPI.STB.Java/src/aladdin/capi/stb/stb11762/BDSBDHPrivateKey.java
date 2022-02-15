package aladdin.capi.stb.stb11762;
import aladdin.capi.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////
// Личный ключ подписи и обмена
///////////////////////////////////////////////////////////////////////
public class BDSBDHPrivateKey extends aladdin.capi.PrivateKey implements IBDSBDHPrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 46867149323035704L;
    
    // параметры ключа 
    private final IBDSBDHParameters parameters; 
    // секретные значения
    private final BigInteger bdsX; private final BigInteger bdhX;
    
    // конструктор
	public BDSBDHPrivateKey(Factory factory, SecurityObject scope, 
        String keyOID, IBDSBDHParameters parameters, BigInteger bdsX, BigInteger bdhX) 
	{ 	
        // сохранить переданные параметры
		super(factory, scope, keyOID); this.parameters = parameters; 
        
        // сохранить переданные параметры
        this.bdsX = bdsX; this.bdhX = bdhX;
    } 
    // параметры ключа
	@Override public final IBDSBDHParameters parameters() { return parameters; } 
    // секретные значения
	@Override public final BigInteger bdsX() { return bdsX; }
	@Override public final BigInteger bdhX() { return bdhX; }
}
