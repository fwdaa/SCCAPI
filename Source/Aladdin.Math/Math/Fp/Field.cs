using System; 

namespace Aladdin.Math.Fp
{
    ///////////////////////////////////////////////////////////////////////////
    // Поле по простому модулю (Fp)
    ///////////////////////////////////////////////////////////////////////////
    public class Field : Math.Field<BigInteger>, IEquatable<Field>
    {
        // величина модуля
        private BigInteger p;

        // конструктор
        public Field(BigInteger p) { this.p = p; }

        // вернуть модуль поля
        public BigInteger P { get { return p; }}

        // размерность поля
        public override int Dimension { get { return P.BitLength; }}

        // сравнение полей
        public virtual bool Equals(Field other)
        {
            // сравнение полей
            return p.Equals(other.p);
        }
        public override bool Equals(object other)
        {
		    // проверить совпадение экземпляров
		    if (other == this) return true;
			
            // проверить тип элемента
		    if (!(other is Field)) return false;
	
            // сравнить значения элементов
		    return Equals((Field)other);
        }
        // получить хэш-код объекта
        public override int GetHashCode() { return p.GetHashCode(); }

        ///////////////////////////////////////////////////////////////////////
        // Специальные элементы
        ///////////////////////////////////////////////////////////////////////
        public override bool IsZero(BigInteger a)
        {
		    return a.Signum == 0;
        }
        // нулевой и единичный элементы
        public override BigInteger Zero { get { return BigInteger.Zero; }}
        public override BigInteger One  { get { return BigInteger.One;  }}

        ///////////////////////////////////////////////////////////////////////
        // Операции аддитивной группы
        ///////////////////////////////////////////////////////////////////////
        public override BigInteger Negate(BigInteger a)
        {
		    // вычислить противоположный элемент
		    return p.Subtract(a);
        }
        public override BigInteger Add(BigInteger a, BigInteger b)
        {
		    // сложить с элементом поля
		    return a.Add(b).Mod(p);
        }
        public override BigInteger Subtract(BigInteger a, BigInteger b)
        {
            // вычесть элемент поля
            a = a.Subtract(b); return (a.Signum >= 0) ? a : a.Add(p); 
        }
        public override BigInteger Multiply(BigInteger a, BigInteger b)
        {
		    // умножить на элемент поля
		    return a.Multiply(b).Mod(p);
        }
        ///////////////////////////////////////////////////////////////////////
        // Операции мультипликативной группы
        ///////////////////////////////////////////////////////////////////////
        public override BigInteger Invert(BigInteger a)
        {
		    // вычислить обратный элемент
		    return a.ModInverse(p);
        }
        public override BigInteger Product(BigInteger a, BigInteger b)
        {
		    // умножить на элемент поля
		    return a.Multiply(b).Mod(p);
        }
        public override BigInteger Divide(BigInteger a, BigInteger b)
        {
		    // умножить на обратный элемент
		    return a.Multiply(b.ModInverse(p)).Mod(p);
        }
        public override BigInteger Power(BigInteger a, BigInteger b)
        {
		    // возвести в степень
		    return a.ModPow(b, p);
        }
        ///////////////////////////////////////////////////////////////////////
        // Сгенерировать случайное число
        ///////////////////////////////////////////////////////////////////////
        public BigInteger Generate(Random random)
        {
            // проверить наличие генератора
            if (random == null) throw new ArgumentException(); 
        
            // определить требуемое число битов
            int bits = p.BitLength; BigInteger value;
        
            // выделить буфер для генерации
            byte[] buffer = new byte[(bits + 7) / 8];
            do {
                // сгенерировать случайные данные
                random.NextBytes(buffer);

                // очистить неиспользуемые биты
                if ((bits % 8) != 0) buffer[0] &= (byte)((1 << (bits % 8)) - 1); 
        
                // создать большое число 
                value = new BigInteger(1, buffer);
            }
            // проверить выполнение условий генерации
            while (value.CompareTo(p) >= 0); return value; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Вычисление z квадратного корня z^2 = g (второй корень = p - z)
        // Генератор случайных данных используется при p = 8u + 1
        ///////////////////////////////////////////////////////////////////////
        public BigInteger Sqrt(BigInteger g)
        {
            // для p = 4u + 3
            if (p.TestBit(1)) { BigInteger u = p.ShiftRight(2); 
        
                // вычислить y = g^{u + 1} mod p
                BigInteger y = Power(g, u.Add(BigInteger.One)); 
            
                // проверить y^2 = g mod p
                return (Sqr(y).Equals(g)) ? y :  null; 
            }
            // для p = 8u + 5
            else if (p.TestBit(2)) { BigInteger u = p.ShiftRight(3); 
        
                // вычислить gamma = (2g)^u mod p
                BigInteger g2 = Twice(g); BigInteger gamma = Power(g2, u); 
            
                // вычислить i = (2g)gamma^2 mod p
                BigInteger i = Product(g2, Sqr(gamma)); 
            
                // вычислить y = g gamma (i-1) mod p
                BigInteger y = Product(Product(g, gamma), Subtract(i, BigInteger.One)); 

                // проверить y^2 = g mod p
                return (Sqr(y).Equals(g)) ? y : null; 
            }
            // для p = 4u + 1
            else { BigInteger u2_1 = p.ShiftRight(1).Add(BigInteger.One); 
        
                // указать начальные условия
                BigInteger[] UV; BigInteger Q4 = Multiply(g, BigInteger.ValueOf(4)); 
                do {
                    // сгенерировать случайное число
                    BigInteger P = BigInteger.Zero; while (IsZero(P)) P = Generate(new Random()); 
                
                    // вычислить (2u + 1)-элемент Лукаса 
                    BigInteger Q = g; UV = LucasSequence(P, Q, u2_1); 
                
                    // при выполнении условия U = 0 или V^2 = 4Q (mod p)
                    if (IsZero(UV[0]) || Sqr(UV[1]).Equals(Q4)) 
                    {
                        // выполнить деление на два
                        if (UV[1].TestBit(0)) UV[1] = UV[1].Add(p); return UV[1].ShiftRight(1);                    
                    }
                }
                // проверить условие 
                while (!IsZero(UV[1])); 
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Последовательность Лукаса
        ///////////////////////////////////////////////////////////////////////
        // U0 = 0, U1 = 1, U_{k} = P U_{k-1} - Q U_{k-2}
        // V0 = 2, V1 = P, V_{k} = P V_{k-1} - Q V_{k-2}
        ///////////////////////////////////////////////////////////////////////
        private BigInteger[] LucasSequence(BigInteger P, BigInteger Q, BigInteger k) 
        {
            // вычислить delta = P^2 - 4Q
            BigInteger delta = Subtract(Sqr(P), Multiply(Q, BigInteger.ValueOf(4))); 
        
            // указать начальные условия
            BigInteger U = BigInteger.One; BigInteger V = P; 
        
            // для всех битов
            for (int i = k.BitLength - 2; i >= 0; i--)
            {
                // выполнить вычисления
                bool bit = k.TestBit(i); BigInteger T = Product(U, V); 
            
                // выполнить вычисления
                V = Add(Sqr(V), Product(delta, Sqr(U))); U = T;
            
                // выполнить деление на два
                if (V.TestBit(0)) V = V.Add(p); V = V.ShiftRight(1); 
            
                // выполнить вычисления
                if (bit) { T = Add(Product(P, U), V); 
            
                    // выполнить деление на два
                    if (T.TestBit(0)) T = T.Add(p); T = T.ShiftRight(1); 
            
                    // выполнить вычисления
                    V = Add(Product(P, V), Product(delta, U)); U = T;
                
                    // выполнить деление на два
                    if (V.TestBit(0)) V = V.Add(p); V = V.ShiftRight(1); 
                }
            }
            // вернуть результат
            return new BigInteger[] { U, V }; 
        }
    }
}
