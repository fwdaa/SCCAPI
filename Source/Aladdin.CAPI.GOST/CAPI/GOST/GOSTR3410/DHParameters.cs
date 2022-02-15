namespace Aladdin.CAPI.GOST.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры ГОСТ Р 34.10-1994
    ///////////////////////////////////////////////////////////////////////////
    public class DHParameters : IDHParameters
    {
        // конструктор 
        public DHParameters(Math.BigInteger p, Math.BigInteger q, Math.BigInteger a, 
            ASN1.ISO.AlgorithmIdentifier validationParameters)
        {
            this.p                      = p;                    // параметр P
            this.q                      = q;                    // параметр Q
            this.a                      = a;                    // параметр A
            this.validationParameters   = validationParameters; // параметры проверки
        }
        // конструктор 
        public DHParameters(ASN1.GOST.GOSTR3410ParamSet1994 parameters) 
        {
            // сохранить переданные параметры
            this.p = parameters.P.Value; this.q = parameters.Q.Value; 
        
            // сохранить переданные параметры
            this.a = parameters.A.Value; 

            // сохранить переданные параметры
            this.validationParameters = parameters.ValidationAlgorithm; 
        }
	    public Math.BigInteger              P                    { get { return p;                    }}
	    public Math.BigInteger              Q                    { get { return q;                    }}
	    public Math.BigInteger              G                    { get { return a;                    }}
        public ASN1.ISO.AlgorithmIdentifier ValidationParameters { get { return validationParameters; }}
    
	    private Math.BigInteger                 p                   ;   // параметр P
	    private Math.BigInteger                 q                   ;   // параметр Q
	    private Math.BigInteger                 a                   ;   // параметр A
        private ASN1.ISO.AlgorithmIdentifier    validationParameters;   // параметры проверки
    }
}
