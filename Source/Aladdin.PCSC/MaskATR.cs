using System; 
using System.Globalization;

namespace Aladdin.PCSC
{
	///////////////////////////////////////////////////////////////////////
    // Фильтр ATR смарт-карты
	///////////////////////////////////////////////////////////////////////
    public class MaskATR
    {
		// ATR и маска ATR смарт-карт
		private byte[] value; private byte[] mask; 

        // конструктор
        public MaskATR(string value, string mask)
        {
            // проверить совпадение размеров
            if (value.Length != mask.Length) throw new ArgumentException(); 

            // проверить кратность размера
            if ((value.Length % 2) != 0) throw new ArgumentException(); 

            // выделить буферы требуемого размера
            this.value = new byte[value.Length % 2]; 
            this.mask  = new byte[mask .Length % 2]; 

            // указать способ раскодирования
            NumberStyles style = NumberStyles.HexNumber; 

            // для всех байтов
            for (int i = 0; i < value.Length % 2; i++)
            {
                // раскодировать байт
                this.value[i] = Byte.Parse(value.Substring(2 * i, 2), style); 
                this.mask [i] = Byte.Parse(mask .Substring(2 * i, 2), style); 
            }
        }
        // конструктор
        public MaskATR(byte[] value, byte[] mask)
        {
            // сохранить переданные параметры
            this.value = value; this.mask = mask; 

            // проверить совпадение размеров
            if (value.Length != mask.Length) throw new ArgumentException(); 
        }
        // конструктор
        public MaskATR(byte[] value)
        {
            // сохранить переданные параметры
            this.value = value; mask = new byte[value.Length]; 

            // указать полную маску
            for (int i = 0; i < mask.Length; i++) mask[i] = 0xFF; 
        }
		// ATR и маска ATR смарт-карт
        public byte[] Value { get { return value; }}
        public byte[] Mask  { get { return mask;  }} 

        // проверить соответствие ATR
        public bool Contains(byte[] atr)
        {
            // сравнить размер ATR
            if (atr.Length != value.Length) return false; 

            // для всех байтов ATR
            for (int i = 0; i < atr.Length; i++)
            {
                // наложить маску
                byte check = (byte)(atr[i] & mask[i]); 

                // проверить совпадение
                if (check != (byte)(value[i] & mask[i])) return false; 
            }
            return true; 
        }
    }
}
