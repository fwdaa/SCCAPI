using System; 

///////////////////////////////////////////////////////////////////////////
// Параметры эллиптических кривых
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.GOSTR3410
{
    [Serializable]
    public class ECParameters : IECParameters
    {
        // конструктор 
        public ECParameters(EC.CurveFp ec, EC.Point p, Math.BigInteger q)
        {
            this.ec  = ec; // эллиптическая кривая
            this.p   = p;  // базовая точка P
            this.q   = q;  // порядок базовой точки
        }
        // конструктор 
        public ECParameters(ASN1.GOST.GOSTR3410ParamSet parameters)

            // сохранить переданные параметры
            : this(new EC.CurveFp(parameters.P.Value, 
                parameters.A.Value, parameters.B.Value, null
                ), new EC.Point(parameters.X.Value, parameters.Y.Value
                ), parameters.Q.Value
        ) {} 
	    public EC.CurveFp       Curve     { get { return ec; }}
	    public EC.Point         Generator { get { return p;  }}
	    public Math.BigInteger	Order     { get { return q;  }}
    
        private EC.CurveFp      ec; // эллиптическая кривая
        private EC.Point        p;  // базовая точка P
        private Math.BigInteger q;  // порядок базовой точки
    }
}