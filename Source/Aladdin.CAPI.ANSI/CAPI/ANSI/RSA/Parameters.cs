using System; 

namespace Aladdin.CAPI.ANSI.RSA
{
    ///////////////////////////////////////////////////////////////////////////////
    // Параметры RSA
    ///////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class Parameters : IParameters
    {
        // преобразовать параметры алгоритма
        public static IParameters Convert(CAPI.IParameters parameters)
        {
            // при полном указании параметров преобразовать тип параметров
            if (parameters is IParameters) return (IParameters)parameters;
    
            // указать параметры алгоритма
            return new Parameters((IKeyBitsParameters)parameters); 
        }
        // размер модуля в битах и величина экспоненты
        private int modulusBits; private Math.BigInteger publicExponent;
    
        // конструктор
        public Parameters(int modulusBits, Math.BigInteger publicExponent) 
        { 
            // проверить размер модуля в битах
		    if (384 > modulusBits || modulusBits > 16384) throw new ArgumentException();
        
            // сохранить переданные параметры
            this.modulusBits = modulusBits; this.publicExponent = publicExponent; 
        } 
        // конструктор
        public Parameters(int modulusBits) 
        { 
            // проверить размер модуля в битах
		    if (384 > modulusBits || modulusBits > 16384) throw new ArgumentException();
        
            // сохранить переданные параметры
            this.modulusBits = modulusBits; publicExponent = Math.BigInteger.ValueOf(0x10001L);
        } 
        // конструктор
        public Parameters(IKeyBitsParameters parameters) : this(parameters.KeyBits) {}
        
        // размер модуля в битах
        public int KeyBits { get { return modulusBits; }}
    
        // величина открытой экспоненты
        public Math.BigInteger PublicExponent { get { return publicExponent; }}
    } 
}
