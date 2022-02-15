namespace Aladdin.CAPI.ANSI.RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Открытый ключ алгоритма RSA
	///////////////////////////////////////////////////////////////////////////
	public class PublicKey : CAPI.PublicKey, IPublicKey
	{
        // параметры открытого ключа 
	    private Math.BigInteger modulus; private Math.BigInteger publicExponent;

        // конструктор
	    public PublicKey(CAPI.KeyFactory keyFactory, 
            Math.BigInteger modulus, Math.BigInteger publicExponent) : base(keyFactory)
        { 
            // сохранить переданные параметры
		    this.modulus = modulus; this.publicExponent = publicExponent;
	    }
        // параметры ключа
	    public override CAPI.IParameters Parameters 
        { 
            // параметры ключа
            get { return new Parameters(modulus.BitLength, publicExponent); }
        }
	    public virtual Math.BigInteger Modulus        { get { return modulus;		 }}
	    public virtual Math.BigInteger PublicExponent { get { return publicExponent; }}
	}
}
