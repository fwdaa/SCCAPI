package aladdin.capi.ansi.rsa;
import aladdin.capi.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма RSA
///////////////////////////////////////////////////////////////////////////
public class PrivateKey extends aladdin.capi.PrivateKey implements IPrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 2577778688690386324L;
    
	private final BigInteger    modulus;		// параметр N
	private final BigInteger    publicExponent;	// параметр E
	private final BigInteger    privateExponent;// параметр D
	private final BigInteger    prime1;         // параметр P
	private final BigInteger    prime2;         // параметр Q
	private final BigInteger    exponent1;		// параметр D (mod P-1)
	private final BigInteger    exponent2;		// параметр D (mod Q-1)
	private final BigInteger    coefficient;	// параметр Q^{-1}(mod P)

    // конструктор
	public PrivateKey(Factory factory, SecurityObject scope, 
        String keyOID, BigInteger modulus, 
        BigInteger publicExponent, BigInteger privateExponent, 
        BigInteger prime1, BigInteger prime2, BigInteger exponent1, 
		BigInteger exponent2, BigInteger coefficient)
	{
        // сохранить переданные параметры
        super(factory, scope, keyOID); 
        
        this.modulus		 = modulus;         // параметр N
        this.publicExponent  = publicExponent;	// параметр E
        this.privateExponent = privateExponent;	// параметр D
        this.prime1          = prime1;          // параметр P
        this.prime2          = prime2;          // параметр Q
        
        // сохранить значение параметра
        if (exponent1 != null) this.exponent1 = exponent1;
        else {
            // вычислить значение параметра
            this.exponent1 = privateExponent.mod(prime1); 
        }
        // сохранить значение параметра
        if (exponent2 != null) this.exponent2 = exponent2;
        else {
            // вычислить значение параметра
            this.exponent2 = privateExponent.mod(prime2); 
        }
        // сохранить значение параметра
        if (coefficient != null) this.coefficient = coefficient;
        else {
            // вычислить значение параметра
            this.coefficient = prime2.modInverse(prime1); 
        }
	}
    // параметры ключа
	@Override public final IParameters parameters() 
    { 
        // параметры ключа
        return new Parameters(getModulus().bitLength(), getPublicExponent()); 
    }
    // параметры ключа
	@Override public final BigInteger getModulus        () { return modulus;           }
	@Override public final BigInteger getPublicExponent () { return publicExponent;	   }
	@Override public final BigInteger getPrivateExponent() { return privateExponent;   }
	@Override public final BigInteger getPrimeP         () { return prime1;            }
	@Override public final BigInteger getPrimeQ         () { return prime2;            }
	@Override public final BigInteger getPrimeExponentP () { return exponent1;         }
	@Override public final BigInteger getPrimeExponentQ () { return exponent2;         }
	@Override public final BigInteger getCrtCoefficient	() { return coefficient;       }
}
