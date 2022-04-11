package aladdin.capi.ansi.rsa;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма RSA
///////////////////////////////////////////////////////////////////////////
public class PublicKey extends aladdin.capi.PublicKey implements IPublicKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = -6578367713941521342L;

    // параметры открытого ключа 
	private final BigInteger modulus; private final BigInteger publicExponent;

    // конструктор
	public PublicKey(aladdin.capi.KeyFactory keyFactory, BigInteger modulus, BigInteger publicExponent) 
    { 
        // сохранить переданные параметры
		super(keyFactory); this.modulus = modulus; this.publicExponent = publicExponent;
	}
    // параметры ключа
	@Override public final aladdin.capi.IParameters parameters() 
    { 
        // параметры ключа
        return new Parameters(modulus.bitLength(), publicExponent); 
    }
    // параметры открытого ключа 
	@Override public final BigInteger getModulus       () { return modulus;		   }
	@Override public final BigInteger getPublicExponent() { return publicExponent; }
}
