using System; 

namespace Aladdin.CAPI.ANSI.RSA
{
    ///////////////////////////////////////////////////////////////////////////////
    // Параметры RSA
    ///////////////////////////////////////////////////////////////////////////////
    public class Parameters : IParameters
    {
        // размер модуля в битах и величина экспоненты
        private int modulusBits; private Math.BigInteger publicExponent;
    
        // конструктор
        public Parameters(int modulusBits, Math.BigInteger publicExponent) 
        { 
            // проверить размер модуля в битах
		    if (384 > modulusBits || modulusBits > 16384) throw new ArgumentException();
        
            // сохранить переданные параметры
            this.modulusBits = modulusBits; 

            // сохранить переданные параметры
            if (publicExponent != null) this.publicExponent = publicExponent; 
        
            // указать значение параметра по умолчанию
            else this.publicExponent = Math.BigInteger.ValueOf(0x10001L); 
        } 
        // размер модуля в битах
        public int KeySize { get { return modulusBits; }}
    
        // величина открытой экспоненты
        public Math.BigInteger PublicExponent { get { return publicExponent; }}
    } 
}
