using System; 

namespace Aladdin.Math 
{
    ///////////////////////////////////////////////////////////////////////
    // Вектор (a_0, ..., a_{m-1}). Внутренее представление magnitude: 
    // первое слово содержит биты [a_0, a_1, ...], последнее слово 
    // содержит биты [..., a_{m-1}]. При преобразовании вектора в число 
    // создаваемое число имеет вид: a_0 2^{m-1} + ... + a_{m-2} 2 + a_{m-1}. 
    ///////////////////////////////////////////////////////////////////////
    public sealed class Vector : IEquatable<Vector>
    {
        // коэффициенты вектора
        private UInt32[] magnitude; private int m; 

        // нулевой вектор
        public static Vector Zeros(int m) { return new Vector(m); }
        // вектор из единиц
        public static Vector Ones(int m) 
        {
            // создать буфер для битов
            UInt32[] magnitude = new UInt32[(m + 31) / 32]; 
        
            // заполнить буфер единицами
            for (int i = 0; i < magnitude.Length; i++) magnitude[i] = 0xFFFFFFFF;

            // очистить неиспользуемые биты
            if ((m % 32) != 0) magnitude[0] &= (1u << (m % 32)) - 1; 
        
            // вернуть вектор из единиц
            return new Vector(magnitude, m); 
        }
        // конструктор
        public Vector(Random random, int m) 
        {
            // проверить наличие генератора
            if (random == null) throw new ArgumentException(); 
        
            // сгенерировать случайные данные
            byte[] encoded = new byte[(m + 7) / 8]; random.NextBytes(encoded);
        
            // очистить неиспользуемые биты
            if ((m % 8) != 0) encoded[0] &= (byte)((1 << (m % 8)) - 1); 
        
            // преобразовать массив байтов в массив 32-битных слов 
            magnitude = Utils.BitsToUints(encoded, m); this.m = m; 
        }
        // конструктор
        public Vector(BigInteger value, int m) 
        {
            // определить требуемый размер
            int cb = (m + 7) / 8; Endian endian = Endian.BigEndian; 
        
            // получить закодированное представление
            byte[] encoded = Convert.FromBigInteger(value, endian, cb); 
            
            // преобразовать массив байтов в массив 32-битных слов 
            magnitude = Utils.BitsToUints(encoded, m); this.m = m; 
        }
        // конструктор
        internal Vector(UInt32[] magnitude, int m)
        {
            // сохранить переданные параметры
            this.magnitude = magnitude; this.m = m; 
        }
        // конструктор
        private Vector(int m) : this(new UInt32[(m + 31) / 32], m) {}

        // преобразовать в число
        public BigInteger ToBigInteger() 
        { 
            // преобразовать массив слов в массив байтов
            byte[] encoded = Utils.UintsToBits(magnitude, m); 

            // раскодировать число
            return new BigInteger(1, encoded); 
        }
        // преобразовать в многочлен
        public Polynom ToPolynom() 
        { 
            // преобразовать в многочлен
            return new Polynom((UInt32[])magnitude.Clone()); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Унаследованные методы
        ///////////////////////////////////////////////////////////////////////
        public override bool Equals(Object other)
        {
		    // проверить совпадение экземпляров
		    if (other == this) return true;

		    // проверить тип элемента
		    if (!(other is Vector)) return false;

		    // сравнить значения элементов
		    return Equals((Vector)other);
        }
        public override int GetHashCode()
        {
		    // учесть размер числа
            int hc = m; if (hc == 0) return hc;

		    // учесть первое слово
		    hc ^= (int)magnitude[0]; if (magnitude.Length != 1)
		    {
			    // учесть последнее слово
			    hc ^= (int)magnitude[magnitude.Length - 1];
		    }
		    return hc;
        }
        ///////////////////////////////////////////////////////////////////////
        // Сравнение векторов
        ///////////////////////////////////////////////////////////////////////
        public bool Equals(Vector other)
        {
		    // сравнить размеры многочленов
		    if (m != other.m) return false;
	
		    // для всех коэффициентов многочлена
		    for (int i = 0; i < magnitude.Length; i++)
		    {
                // проверить совпадение коэффициентов
                if (magnitude[i] != other.magnitude[i]) return false;
		    }
		    return true;
        }
        ///////////////////////////////////////////////////////////////////////
        // Свойства вектора
        ///////////////////////////////////////////////////////////////////////

        // число битов вектора
        public int M { get { return m; }}
    
        // получить значение бита
        public bool TestBit(int index) { return this[index] != 0; }

        // получить значение бита
        public int this[int index] { get 
        {
            // определить позицию бита
            int word = (m - 1 - index) / 32; int bit = (m - 1 - index) % 32; 
        
            // вернуть значение бита
            return ((magnitude[magnitude.Length - 1 - word] & (1 << bit)) != 0) ? 1 : 0; 
        }}
        ///////////////////////////////////////////////////////////////////////
        // операции над векторами
        ///////////////////////////////////////////////////////////////////////
        public Vector Rcr(int n) { return Rcl(m - n); }
        public Vector Rcl(int n)
        {
            // проверить необходимость действий
            if (magnitude.Length == 0) return this;  
        
    	    // проверить на нулевой сдвиг
		    if (n < 0) return Rcr(-n); if ((n %= m) == 0) return this;

		    // выделить память для результата
		    UInt32[] result = new UInt32[magnitude.Length]; int words = n / 32; n %= 32;
        
            // определить число неиспользуемых битов первого слова
            int unused = (32 - (m % 32)) % 32; int used = 32 - unused; 
         
            // для всех разрядов, извлекаемых справа 
            int i = 0; for (; i < magnitude.Length - 1 - words; i++)
            {
                // выполнить соответствующие сдвиги
                result[i] = (magnitude[words + i] << n) | (magnitude[words + i + 1] >> (32 - n));
            }
            // выполнить соответствующие сдвиги
            result[i] = (magnitude[words + i] << n) | ((magnitude[0] << unused) >> (32 - n)); 
            
            // извлечь недостающие биты из второго слова
            if (n > used) result[i] |= magnitude[1] >> (32 - (n - used));           

            // пересчитать величину сдвига и для оставшихся разрядов
            for (n = (n + unused) % 32, i++; i < magnitude.Length; i++)
            {
                // вычислить индекс элемента
                int j = i - (magnitude.Length - words); 

                // выполнить соответствующие сдвиги
                result[i] = (magnitude[j] << n) | (magnitude[j + 1] >> (32 - n));
            }
            // удалить неиспользуемые биты
            if (unused > 0) result[0] &= (1u << used) - 1; 
        
            // вернуть реультат
            return new Vector(result, m);
        }
        public Vector Add(Vector B)
        {
            // проверить совпадение размерности
            if (B.M != m) throw new ArgumentException(); 
        
            // скопировать первый вектор
            UInt32[] result = (UInt32[])magnitude.Clone();

		    // сложить многочлены
		    for (int i = 0; i < magnitude.Length; i++) result[i] ^= B.magnitude[i];
		
		    // вернуть многочлен
		    return new Vector(result, m);
        }
        // скалярное умножение векторов
        public int Product(Vector B)
        {
            // проверить корректность 
            if (B.M != m) throw new ArgumentException(); int r = 0;
        
            // для всех слов
            for (int i = 0; i < magnitude.Length; i++)
            {
                // выполнить логическую операцию
                UInt32 word = magnitude[i] & B.magnitude[i]; 
            
                // для всех битов слов
                for (int mask = 1; mask != 0; mask <<= 1)
                {
                    // проверить значение бита
                    if ((word & mask) != 0) r ^= 1; 
                }
            }
            return r; 
        }
        // умножение на матрицу справа
        public Vector Product(Matrix matrix)
        {
            // получить список столбцов
            Vector[] columns = matrix.Columns; 
        
            // выделить память для результата
            VectorBuilder result = new VectorBuilder(columns.Length); 
        
            // для всех столбцов матрицы
            for (int i = 0; i < columns.Length; i++)
            {
                // вычислить скалярное произведение
                result[i] = Product(columns[i]); 
            }
            // вернуть результат
            return result.ToVector(); 
        }
    }
}