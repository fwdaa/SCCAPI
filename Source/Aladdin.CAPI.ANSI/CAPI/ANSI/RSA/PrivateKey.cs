using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ алгоритма RSA
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class PrivateKey : CAPI.PrivateKey, IPrivateKey
	{
	    private Math.BigInteger modulus;		// параметр N
	    private Math.BigInteger publicExponent;	// параметр E
	    private Math.BigInteger privateExponent;// параметр D
	    private Math.BigInteger prime1;         // параметр P
	    private Math.BigInteger prime2;         // параметр Q
	    private Math.BigInteger exponent1;		// параметр D (mod P-1)
	    private Math.BigInteger exponent2;		// параметр D (mod Q-1)
	    private Math.BigInteger coefficient;	// параметр Q^{-1}(mod P)

        // конструктор
	    public PrivateKey(CAPI.Factory factory, SecurityObject scope, string keyOID, 
            Math.BigInteger modulus, Math.BigInteger publicExponent, 
            Math.BigInteger privateExponent, Math.BigInteger prime1, 
            Math.BigInteger prime2, Math.BigInteger exponent1, 
		    Math.BigInteger exponent2, Math.BigInteger coefficient) : base(factory, scope, keyOID)
	    {
            this.modulus		 = modulus;         // параметр N
            this.publicExponent  = publicExponent;	// параметр E
            this.privateExponent = privateExponent;	// параметр D
            this.prime1          = prime1;          // параметр P
            this.prime2          = prime2;          // параметр Q
        
            // сохранить значение параметра
            if (exponent1 != null) this.exponent1 = exponent1;
            else {
                // вычислить значение параметра
                this.exponent1 = privateExponent.Mod(prime1); 
            }
            // сохранить значение параметра
            if (exponent2 != null) this.exponent2 = exponent2;
            else {
                // вычислить значение параметра
                this.exponent2 = privateExponent.Mod(prime2); 
            }
            // сохранить значение параметра
            if (coefficient != null) this.coefficient = coefficient;
            else {
                // вычислить значение параметра
                this.coefficient = prime2.ModInverse(prime1); 
            }
	    }
        // параметры ключа
	    public override CAPI.IParameters Parameters 
        { 
            // параметры ключа
            get { return new Parameters(Modulus.BitLength, PublicExponent); }
        }
        // параметры ключа
	    public virtual Math.BigInteger Modulus         { get { return modulus;         }}
	    public virtual Math.BigInteger PublicExponent  { get { return publicExponent;  }}
	    public virtual Math.BigInteger PrivateExponent { get { return privateExponent; }}
	    public virtual Math.BigInteger PrimeP          { get { return prime1;          }}
	    public virtual Math.BigInteger PrimeQ          { get { return prime2;          }}
	    public virtual Math.BigInteger PrimeExponentP  { get { return exponent1;       }}
	    public virtual Math.BigInteger PrimeExponentQ  { get { return exponent2;       }}
	    public virtual Math.BigInteger CrtCoefficient  { get { return coefficient;     }}
    }
}
