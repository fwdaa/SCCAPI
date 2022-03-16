using System; 

namespace Aladdin.Math 
{
    ///////////////////////////////////////////////////////////////////////
    // Многочлен (a_0 x^m + ... + a_{m-1} x^1 + a_m). Внутренее представление
    // magnitude: первое слово содержит биты [a_0, a_1, ...], последнее слово 
    // содержит биты [..., a_{m-1}, a_m]. Размерность многочлена не содержится
    // в классе и определяется последним ненулевым коэффициентом при наибольшей 
    // степени. При преобразовании многочлена в вектор число координат вектора
    // необходимо указывать для определения фиксированного размера представления 
    // вектора. При преобразовании многочлена в число создаваемое число имеет 
    // вид: a_0 2^m + ... + a_{m-1} 2 + a_m, т.е. в младших разрядах содержит
    // коэффициенты при младших степенях. 
    ///////////////////////////////////////////////////////////////////////
    [Serializable]
    public sealed class Polynom : IEquatable<Polynom>
    {
        // коэффициенты многочлена от старших к младшим
        private UInt32[] magnitude; 

        // нулевое многочлен
        public static readonly Polynom Zero = new Polynom();
        // единичный многочлен
        public static readonly Polynom One = new Polynom(new UInt32[] {1});

        ///////////////////////////////////////////////////////////////////////
        // Создание многочлена
        ///////////////////////////////////////////////////////////////////////
        public Polynom() { magnitude = new UInt32[0]; }

        // конструктор
        public Polynom(Math.BigInteger value)
        {
            // получить закодированное представление
            byte[] encoded = value.ToByteArray(); if (encoded[0] == 0)
            {
                // удалить незначимый байт
                encoded = Arrays.CopyOf(encoded, 1, encoded.Length - 1);
            }
            // выполнить преобразование
            magnitude = Utils.BitsToUints(encoded, encoded.Length * 8); 
        }
        // конструктор
        internal Polynom(UInt32[] magnitude)
        {
		    // пропустить незначимые старшие слова
		    int i; for (i = 0; i < magnitude.Length && magnitude[i] == 0; i++) {}

            // выделить буфер требуемого размера
            this.magnitude = new UInt32[magnitude.Length - i]; 

		    // скопировать многочлен
		    Array.Copy(magnitude, i, this.magnitude, 0, this.magnitude.Length);
        }
        ///////////////////////////////////////////////////////////////////////
        // Свойства многочлена
        ///////////////////////////////////////////////////////////////////////
        public Math.BigInteger ToBigInteger()
        {
            // получить закодированное представление
            byte[] encoded = Utils.UintsToBits(magnitude, magnitude.Length * 32); 
        
            // раскодировать большое число
            return new BigInteger(1, encoded); 
	    }
        public Vector ToVector(int bits)
        {
            // проверить корректность преобразования
            if ((bits + 31) / 32 < magnitude.Length)
            {
                // при ошибке выбросить исключение
                throw new ArgumentException(); 
            }
            // выделить массив требуемого размера
            UInt32[] result = new UInt32[(bits + 31) / 32]; 
        
		    // скопировать первый многочлен
		    Array.Copy(magnitude, 0, result, 
                result.Length - magnitude.Length, magnitude.Length
            );
            // создать вектор
            return new Vector(result, bits); 
	    }
        public int BitLength { get 
        {
            // определить число битов
            return Utils.BitLength(1, magnitude, 0, magnitude.Length); 
        }}
        // признак нулевого элемента
        public bool IsZero { get { return magnitude.Length == 0; }}

        // получить значение бита
        public int this[int index] { get
        {
            // определить позицию бита
            int word = index / 32; int bit = index % 32; 
        
            // вернуть значение бита
            return ((magnitude[magnitude.Length - 1 - word] & (1 << bit)) != 0) ? 1 : 0; 
        }}
        ///////////////////////////////////////////////////////////////////////
        // Унаследованные методы
        ///////////////////////////////////////////////////////////////////////
        public override bool Equals(Object other)
        {
		    // проверить совпадение экземпляров
		    if (other == this) return true;

		    // проверить тип элемента
		    if (!(other is Polynom)) return false;

		    // сравнить значения элементов
		    return Equals((Polynom)other);
        }
        public override int GetHashCode()
        {
		    // учесть размер числа
            int hc = magnitude.Length; if (hc == 0) return hc;

		    // учесть первое слово
		    hc ^= (int)magnitude[0]; if (magnitude.Length != 1)
		    {
			    // учесть последнее слово
			    hc ^= (int)magnitude[magnitude.Length - 1];
		    }
		    return hc;
        }
        ///////////////////////////////////////////////////////////////////////
        // Сравнение многочленов
        ///////////////////////////////////////////////////////////////////////
        public bool Equals(Polynom other)
        {
		    // сравнить размеры многочленов
		    if (magnitude.Length != other.magnitude.Length) return false;
	
		    // для всех коэффициентов многочлена
		    for (int i = 0; i < magnitude.Length; i++)
		    {
                // проверить совпадение коэффициентов
                if (magnitude[i] != other.magnitude[i]) return false;
		    }
		    return true;
        }
        ///////////////////////////////////////////////////////////////////////
        // Логические сдвиги
        ///////////////////////////////////////////////////////////////////////
        public Polynom ShiftLeft(int n)
        {
    	    // проверить на нулевой многочлен и сдвиг
		    if (magnitude.Length == 0 || n == 0) return this;

		    // выделить память для результата
		    UInt32[] result = new UInt32[magnitude.Length + (n + 31) / 32]; 
        
		    // установить старшие разряды
		    n = n % 32; result[0] = magnitude[0] >> (32 - n);

		    // для всех разрядов
		    for (int i = 1; i < magnitude.Length; i++)
		    {
			    // сдвинуть соответствующие разряды
			    result[i] = (magnitude[i] >> (32 - n)) | (magnitude[i - 1] << n);
		    }
		    // установить младшие разряды
		    result[magnitude.Length] = magnitude[magnitude.Length - 1] << n; 
        
            // вернуть реультат
            return new Polynom(result);
        }
        ///////////////////////////////////////////////////////////////////////
        // Сложение многочленов
        ///////////////////////////////////////////////////////////////////////
        public Polynom Add(Polynom B)
        {
		    // определить размер результата
		    int length = System.Math.Max(magnitude.Length, B.magnitude.Length);

            // выделить память для многочлена
            UInt32[] result = new UInt32[length];  

		    // скопировать первый многочлен
		    Array.Copy(magnitude, 0, result, 
                length - magnitude.Length, magnitude.Length
            );
            // сложить многочлены
		    for (int i = 0; i < B.magnitude.Length; i++)
		    {
                result[length - B.magnitude.Length + i] ^= B.magnitude[i];
		    }
		    // вернуть многочлен
		    return new Polynom(result);
        }
        public Polynom Subtract(Polynom B) { return Add(B); }

        ///////////////////////////////////////////////////////////////////////
        // Умножение многочленов
        ///////////////////////////////////////////////////////////////////////
        public Polynom Product(Polynom B)
        {
    	    // для всех слов многочлена
    	    Polynom R = Zero;
        
		    for (int i = 0; i < magnitude.Length; i++)
		    {
                // для всех битов слова
                for (uint j = 1u << 31; j != 0; j >>= 1)
                {
                    // сдвинуть разряды
				    R = R.ShiftLeft(1);

				    // проверить установку бита
				    if ((magnitude[i] & j) != 0) R = R.Add(B);
                }
		    }
		    return R;
        }
        ///////////////////////////////////////////////////////////////////////
        // Деление многочленов
        ///////////////////////////////////////////////////////////////////////
        public Polynom[] DivideAndRemainder(Polynom B)
        {
		    // определить степень делителя и делимого
		    int bitsB = B.BitLength; int bitsR = BitLength;

		    // проверить необходимость вычислений
		    if (bitsB > bitsR) return new Polynom[] { Zero, this }; 
            else {
                // частное и остаток
                UInt32[] Q = new UInt32[(bitsR - bitsB) / 32 + 1]; Polynom R = this;

                // пока остаток больше делителя
                for (; bitsR >= bitsB; bitsR = R.BitLength)
                {
				    // установить бит частного
				    Q[Q.Length - 1 - (bitsR - bitsB) / 32] |= 1u << ((bitsR - bitsB) % 32);

				    // отнять сдвинутый делитель
				    R = R.Add(B.ShiftLeft(bitsR - bitsB));
                }
                return new Polynom[] { new Polynom(Q), R };
            }
        }
        public Polynom Divide(Polynom B)
        {
            // определить степень делителя и делимого
		    int bitsB = B.BitLength; int bitsR = BitLength;

		    // проверить необходимость вычислений
		    if (bitsB > bitsR) return Zero; 

		    // частное и остаток
		    UInt32[] Q = new UInt32[(bitsR - bitsB) / 32 + 1]; Polynom R = this;

		    // пока остаток больше делителя
		    for (; bitsR >= bitsB; bitsR = R.BitLength)
		    {
                // установить бит частного
                Q[Q.Length - 1 - (bitsR - bitsB) / 32] |= 1u << ((bitsR - bitsB) % 32);

                // отнять сдвинутый делитель
                R = R.Add(B.ShiftLeft(bitsR - bitsB));
            }
		    return new Polynom(Q);
        }
        public Polynom Remainder(Polynom B)
        {
            // определить степень делителя и делимого
		    int bitsB = B.BitLength; int bitsR = BitLength;

		    // проверить необходимость вычислений
		    if (bitsB > bitsR) return this; Polynom R = this;
		
		    // пока остаток больше делителя
		    for (; bitsR >= bitsB; bitsR = R.BitLength)
		    {
                // отнять сдвинутый делитель
                R = R.Add(B.ShiftLeft(bitsR - bitsB));
		    }
		    return R;
        }
    }
}
