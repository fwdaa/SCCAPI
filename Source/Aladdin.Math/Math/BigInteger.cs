using System;
using System.Diagnostics;

namespace Aladdin.Math 
{
	///////////////////////////////////////////////////////////////////////////
	// Большое число
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public class BigInteger : IEquatable<BigInteger>
	{
		///////////////////////////////////////////////////////////////////////
		// Создание больших чисел (внутренние функции)
		///////////////////////////////////////////////////////////////////////
		private BigInteger(int sign, UInt32[] magnitude, bool check)
		{
			// установить знак и массив для большого числа
            if (!check) { this.magnitude = magnitude; this.sign = sign; }
			else {
				// проверить на нулевое число
				if (magnitude.Length == 0) { this.magnitude = Utils.ZeroMagnitude; sign = 0; return; }

				// проверить необходимость переразмещения массива
                if (magnitude[0] != 0) { this.magnitude = magnitude; this.sign = sign; return; } 

				// для всех слов большого числа
                for (int i = 1; i < magnitude.Length; ++i)
				{
					// пропустить незначимые слова
                    if (magnitude[i] == 0) continue; this.sign = sign;

					// выделить новый массив для слов
                    this.magnitude = new UInt32[magnitude.Length - i];

					// скопировать значимые слова
                    Array.Copy(magnitude, i, this.magnitude, 0, magnitude.Length - i); return;
				}
				// число нулевое
				this.magnitude = Utils.ZeroMagnitude; this.sign = 0; 
			}
		}
		// нулевое число
		private BigInteger() { magnitude = Utils.ZeroMagnitude; sign = 0; }

		// знак числа и его слова в формате big endian
        private int sign; private UInt32[] magnitude;

		///////////////////////////////////////////////////////////////////////
		// Создание больших чисел из малых
		///////////////////////////////////////////////////////////////////////
		public static readonly BigInteger Zero  = new BigInteger();

		// частные случаи больших чисел
		public static readonly BigInteger One = new BigInteger(1, new UInt32[] {  1 }, false);
		public static readonly BigInteger Two = new BigInteger(1, new UInt32[] {  2 }, false);

		private static BigInteger ValueOf(UInt64 value)
		{
			switch (value)
            {
			// частные случаи
			case 0: return Zero; case 1: return One; case 2: return Two; 
            }
			// выделить старшие и младшие 32 бита
			UInt32 hi = (UInt32)((value >> 32) & UInt32.MaxValue); 
			UInt32 lo = (UInt32)((value >>  0) & UInt32.MaxValue); 

			// создать большие числа
            if (hi != 0) return new BigInteger(1, new UInt32[] { hi, lo }, false);
			else         return new BigInteger(1, new UInt32[] {     lo }, false);
		}

		public static BigInteger ValueOf(Int64 value)
		{
			// создать положительное число
			if (value >= 0) return ValueOf((UInt64)value);

			// создать минимальное отрицательное число
			if (value == Int64.MinValue) return ValueOf(~value).Not();

			// создать отрицательное число
			return ValueOf(-value).Negate();
		}

        public static implicit operator BigInteger(UInt64 value)
        {
            // создать большое число
            return BigInteger.ValueOf(value);
        }
        public static implicit operator BigInteger(Int64 value)
        {
			// создать большое число
			return BigInteger.ValueOf(value);
		}

		///////////////////////////////////////////////////////////////////////
		// Создание большого числа по его бинарному представлению
		///////////////////////////////////////////////////////////////////////
		public BigInteger(byte[] bytes) 
        {
			// преобразовать массив байт в массив слов
			magnitude = Utils.SBytesToUints(bytes, out sign); 
        }
		public BigInteger(int sign, byte[] bytes)
        {
			// проверить на нулевое число 
			if (sign == 0) { magnitude = Utils.ZeroMagnitude; this.sign = 0; return; }

			// преобразовать массив байт в массив слов
			magnitude = Utils.UBytesToUints(bytes);

			// установить знак числа
			this.sign = (magnitude.Length != 0) ? sign : 0; 
        }
		///////////////////////////////////////////////////////////////////////
		// Преобразование в массив байтов
		///////////////////////////////////////////////////////////////////////
		public byte[] ToByteArray () { return Utils.UintsToBytes(sign, magnitude, false); }

		// определить знак числа и значение
		public  int Signum    { get { return sign; } }
        public long LongValue { get 
        {
			// проверить на нулевое число
			if (sign == 0) return 0; 

			// проверить размер числа
			if (magnitude.Length > 2) throw new InvalidOperationException(); 

			// прочитать младшее слово
			ulong value = magnitude[magnitude.Length - 1];
		
			// при наличии двух слов
			if (magnitude.Length > 1)
			{
				// прочитать второе младшее слово
				value |= magnitude[magnitude.Length - 2] << 32; 
			}
			// учесть знак числа
			return unchecked((sign < 0) ? -(long)value : (long)value);
		}}
        public int IntValue { get 
		{
			// проверить на нулевое число
			if (sign == 0) return 0; 

			// проверить размер числа
			if (magnitude.Length > 1) throw new InvalidOperationException(); 

			// прочитать младшее слово
			uint value = magnitude[magnitude.Length - 1];
		
			// учесть знак числа
			return unchecked((sign < 0) ? -(int)value : (int)value);
		}}
		public static explicit operator Int64(BigInteger value)
		{
			// создать большое число
			return value.LongValue;
		}
		public static explicit operator Int32(BigInteger value)
		{
			// создать большое число
			return value.IntValue;
		}
		///////////////////////////////////////////////////////////////////////
		// Преобразования во встроенный тип
		///////////////////////////////////////////////////////////////////////
#if !NO_NUMERICS
        private static BigInteger FromNumericInteger(System.Numerics.BigInteger value)
        {
			// получить байтовое представление
			byte[] bytes = value.ToByteArray(); Array.Reverse(bytes);

            // вернуть большое число
            return new BigInteger(bytes); 
        }
        private static System.Numerics.BigInteger ToNumericInteger(BigInteger value)
        {
			// получить байтовое представление
			byte[] bytes = value.ToByteArray(); Array.Reverse(bytes);
            
            // вернуть большое число
            return new System.Numerics.BigInteger(bytes); 
        }
#endif 
		///////////////////////////////////////////////////////////////////////
		// Случайная генерация большого числа
		///////////////////////////////////////////////////////////////////////
		public BigInteger(int bits, Random rand)
		{
			// проверить на нулевое число 
			if (bits == 0) { magnitude = Utils.ZeroMagnitude; sign = 0; return; }

			// сгенерировать случайные данные
			byte[] buffer = new byte[(bits + 7) / 8]; rand.NextBytes(buffer);

			// избавиться от лишних битов
			buffer[0] &= (byte)(Byte.MaxValue >> (8 * buffer.Length - bits));

			// преобразовать массив байт в массив слов
			magnitude = Utils.UBytesToUints(buffer);

			// установить знак числа
			sign = (magnitude.Length != 0) ? 1 : 0;
		}

		public BigInteger(int bits, int certainty, Random rand)
		{
			// проверить корректность данных
            Debug.Assert(bits >= 2); sign = 1; 

			// выделить массив для большого числа
			byte[] buffer = new byte[(bits + 7) / 8]; 

            // сгенерировать случайные данные
            if (bits == 2) { rand.NextBytes(buffer); 

				// установить значение большого числа
				if ((buffer[0] & 1) == 0) magnitude = Two.magnitude;

				// установить значение большого числа
				else magnitude = new UInt32[] { 3 }; return; 
			}
			// определить число незначимых битов
			int unused = 8 * buffer.Length - bits;
			for (;;)
			{
				// сгенерировать случайные данные
				rand.NextBytes(buffer); buffer[0] &= (byte)(Byte.MaxValue >> unused);

				// установить старший и младший биты
				buffer[0] |= (byte)(1 << (7 - unused)); buffer[buffer.Length - 1] |= 1;

				// преобразовать массив байт в массив слов
				magnitude = Utils.UBytesToUints(buffer);

				// проверить на простоту с указанной вероятностью
				if (certainty < 1 || CheckProbablePrime(certainty, rand)) break;

				// если число более 32 битов 
				if (magnitude.Length >= 2)
				{
					// выполнить 10000 попыток
					for (int rep = 0; rep < 10000; rep++)
					{
						// сгенерировать случайное смещение
						int offset = rand.Next(1, magnitude.Length);

						// сгенерировать два случайных числа
						UInt32 value1 = unchecked((UInt32)(rand.Next() << 1));
						UInt32 value2 = unchecked((UInt32)(rand.Next() << 1));

						// изменить последнее слово и слово по случайному смещению
						magnitude[magnitude.Length - offset] ^= value1;
						magnitude[magnitude.Length -      1] ^= value2;

						// проверить на простоту с указанной вероятностью
						if (CheckProbablePrime(certainty, rand)) return;
					}
				}
			}
		}
		///////////////////////////////////////////////////////////////////////
		// Унаследованные методы
		///////////////////////////////////////////////////////////////////////
		public static bool operator == (BigInteger A, BigInteger B)
		{
			// сравнить два числа
			return ((object)A != null) ? A.Equals(B) : ((object)B == null);
		}
		public static bool operator != (BigInteger A, BigInteger B)
		{
			// сравнить два числа
			return ((object)A != null) ? !A.Equals(B) : ((object)B != null);
		}
		public bool Equals(BigInteger other)
		{
			// проверить на тождество
			if (Object.ReferenceEquals(other, this)) return true;
			if (other == null) return false;

			// проверить знак числа
			if (other.sign != sign) return false;

			// проверить размер массива
			if (other.magnitude.Length != magnitude.Length) return false;

			// для всех слов массива
			for (int i = 0; i < magnitude.Length; i++)
			{
				// проверить совпадение слова массива
				if (other.magnitude[i] != magnitude[i]) return false;
			}
			return true;
		}
		public override bool Equals(object obj)
		{
			// преобразовать тип объекта
			BigInteger other = obj as BigInteger;

			// сравнить два числа
			return (other != null) ? Equals(other) : false;
		}
		public override int GetHashCode()
		{
			// учесть размер числа
			uint hc = (uint) magnitude.Length; if (hc == 0) return (int)hc; 

			// учесть первое слово
			hc ^= magnitude[0]; if (magnitude.Length > 1)
			{
				// учесть последнее слово
                hc ^= magnitude[magnitude.Length - 1];
			}
			// учесть знак числа
			return unchecked((int)((sign < 0) ? ~hc : hc));
		}
		///////////////////////////////////////////////////////////////////////
		// Сравнение больших чисел
		///////////////////////////////////////////////////////////////////////
		public static bool operator <(BigInteger A, BigInteger B)
		{
			// сравнить два числа
			return A.CompareTo(B) < 0;
		}
		public static bool operator >(BigInteger A, BigInteger B)
		{
			// сравнить два числа
			return A.CompareTo(B) > 0;
		}
		public static bool operator <=(BigInteger A, BigInteger B)
		{
			// сравнить два числа
			return A.CompareTo(B) <= 0;
		}
		public static bool operator >=(BigInteger A, BigInteger B)
		{
			// сравнить два числа
			return A.CompareTo(B) >= 0;
		}
		public int CompareTo(object obj) { return CompareTo((BigInteger)obj); }

		public int CompareTo(BigInteger other)
		{
			// сравнить числа разного знака
			if (sign < other.sign) return -1;
			if (sign > other.sign) return  1; 

			// сравнить нулевые числа
			if (sign == 0) return 0; 

			// сравнить числа одного знака
			return sign * Utils.Compare(magnitude, 0, other.magnitude, 0); 
		}
		public BigInteger Max(BigInteger value)
		{
			return CompareTo(value) > 0 ? this : value;
		}
		public BigInteger Min(BigInteger value)
		{
			return CompareTo(value) < 0 ? this : value;
		}

		///////////////////////////////////////////////////////////////////////
		// Битовые свойства
		///////////////////////////////////////////////////////////////////////
		public int BitCount { get 
		{
			// обработать отрицательное число
			if (sign < 0) return BitLength - Not().BitCount;

			// обработать положительное число
			return Utils.BitCount(magnitude, 0, magnitude.Length); 
		}}
		public int BitLength { get 
		{
			// битовая разрядность числа
			return Utils.BitLength(sign, magnitude, 0, magnitude.Length);
		}}
		///////////////////////////////////////////////////////////////////////
		// Операции с битами
		///////////////////////////////////////////////////////////////////////
		public bool TestBit(int n)
		{
			// обработать отрицательное число
			Debug.Assert(n >= 0); if (sign < 0) return !Not().TestBit(n);

			// определить позицию слова
			int i = n / 32; if (i >= magnitude.Length) return false;

			// проверить установку требуемого бита
			return ((magnitude[magnitude.Length - i - 1] >> (n % 32)) & 1) > 0;
		}
		public BigInteger FlipBit(int n)
		{
            // обработать неположительные числа или несуществующий бит
            if (sign <= 0 || n >= BitLength - 1) return Xor(One.ShiftLeft(n));

            // создать копию массива слов
            Debug.Assert(n >= 0); UInt32[] magCopy = (UInt32[])magnitude.Clone();

            // изменить требуемый бит в новом массиве
			magCopy[magCopy.Length - 1 - (n >> 5)] ^= 1U << (n & 31);

            // создать новое большое число
			return new BigInteger(sign, magCopy, false);
        }
		public BigInteger SetBit(int n)
		{
			// проверить установку требуемого бита
			Debug.Assert(n >= 0); if (TestBit(n)) return this;

            // обработать неположительные числа или несуществующий бит
            if (sign <= 0 || n >= BitLength - 1) return Or(One.ShiftLeft(n));

            // создать копию массива слов
			UInt32[] magCopy = (UInt32[])magnitude.Clone();

            // изменить требуемый бит в новом массиве
			magCopy[magCopy.Length - 1 - (n >> 5)] ^= 1U << (n & 31);

            // создать новое большое число
			return new BigInteger(sign, magCopy, false);
        }
		public BigInteger ClearBit(int n)
		{
			// проверить сброс требуемого бита
			Debug.Assert(n >= 0); if (!TestBit(n)) return this;

            // обработать неположительные числа или несуществующий бит
            if (sign <= 0 || n >= BitLength - 1) return And(One.ShiftLeft(n).Not());

            // создать копию массива слов
			UInt32[] magCopy = (UInt32[])magnitude.Clone();

            // изменить требуемый бит в новом массиве
			magCopy[magCopy.Length - 1 - (n >> 5)] ^= 1U << (n & 31);

            // создать новое большое число
			return new BigInteger(sign, magCopy, false);
        }
		///////////////////////////////////////////////////////////////////////
		// Логические операции
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator ~(BigInteger A)				{ return A.Not( ); }
		public static BigInteger operator &(BigInteger A, BigInteger B) { return A.And(B); }
		public static BigInteger operator |(BigInteger A, BigInteger B) { return A.Or (B); }
		public static BigInteger operator ^(BigInteger A, BigInteger B) { return A.Xor(B); }

		public BigInteger Not() { return Increment().Negate(); }

		public BigInteger And(BigInteger B)
		{
			// проверить на операцию с нулем
			if (sign == 0 || B.sign == 0) return Zero; 

			// определить массивы слов с учетом возможного дополнения
			UInt32[] magA =   sign > 0 ?   magnitude :   Add(One).magnitude;
			UInt32[] magB = B.sign > 0 ? B.magnitude : B.Add(One).magnitude;

			// выделить массив требуемого размера
			UInt32[] magC = new UInt32[System.Math.Max(magA.Length, magB.Length)];

			// определить стартовые позиции
			int startA = magC.Length - magA.Length;
			int startB = magC.Length - magB.Length;

			// определить знак результата
			bool negC = sign < 0 && B.sign < 0;

			// для всех слов результата
			for (int i = 0; i < magC.Length; ++i)
			{
				// извлечь очередное слово
				UInt32 a = (i >= startA) ? magA[i - startA] : 0;
				UInt32 b = (i >= startB) ? magB[i - startB] : 0;

				// при необходимости дополнить слова
				if (sign < 0) a = ~a; if (B.sign < 0) b = ~b;

				// выполнить логическую операцию
				magC[i] = a & b; if (negC) magC[i] = ~magC[i];
			}
			// создать большое число для результата
			BigInteger C = new BigInteger(1, magC, true);

			// установить знак числа
			if (negC) C = C.Not(); return C;
		}

		public BigInteger Or(BigInteger B)
		{
			// проверить на операцию с нулем
			if (sign == 0) return B; if (B.sign == 0) return this; 

			// определить массивы слов с учетом возможного дополнения
			UInt32[] magA =   sign > 0 ?   magnitude :   Add(One).magnitude;
			UInt32[] magB = B.sign > 0 ? B.magnitude : B.Add(One).magnitude;

			// выделить массив требуемого размера
			UInt32[] magC = new UInt32[System.Math.Max(magA.Length, magB.Length)];

			// определить стартовые позиции
			int startA = magC.Length - magA.Length;
			int startB = magC.Length - magB.Length;

			// определить знак результата
			bool negC = sign < 0 || B.sign < 0;

			// для всех слов результата
			for (int i = 0; i < magC.Length; ++i)
			{
				// извлечь очередное слово
				UInt32 a = (i >= startA) ? magA[i - startA] : 0;
				UInt32 b = (i >= startB) ? magB[i - startB] : 0;

				// при необходимости дополнить слова
				if (sign < 0) a = ~a; if (B.sign < 0) b = ~b;

				// выполнить логическую операцию
				magC[i] = a | b; if (negC) magC[i] = ~magC[i];
			}
			// создать большое число для результата
			BigInteger C = new BigInteger(1, magC, true);

			// установить знак числа
			if (negC) C = C.Not(); return C;
		}

		public BigInteger Xor(BigInteger B)
		{
			// проверить на операцию с нулем
			if (sign == 0) return B; if (B.sign == 0) return this; 

			// определить массивы слов с учетом возможного дополнения
			UInt32[] magA =   sign > 0 ?   magnitude :   Add(One).magnitude;
			UInt32[] magB = B.sign > 0 ? B.magnitude : B.Add(One).magnitude;

			// выделить массив требуемого размера
			UInt32[] magC = new UInt32[System.Math.Max(magA.Length, magB.Length)];

			// определить стартовые позиции
			int startA = magC.Length - magA.Length;
			int startB = magC.Length - magB.Length;

			// определить знак результата
			bool negC = (sign != B.sign);

			// для всех слов результата
			for (int i = 0; i < magC.Length; ++i)
			{
				// извлечь очередное слово
				UInt32 a = (i >= startA) ? magA[i - startA] : 0;
				UInt32 b = (i >= startB) ? magB[i - startB] : 0;

				// при необходимости дополнить слова
				if (sign < 0) a = ~a; if (B.sign < 0) b = ~b;

				// выполнить логическую операцию
				magC[i] = a ^ b; if (negC) magC[i] = ~magC[i];
			}
			// создать большое число для результата
			BigInteger C = new BigInteger(1, magC, true);

			// установить знак числа
			if (negC) C = C.Not(); return C;
		}
		///////////////////////////////////////////////////////////////////////
		// Логические сдвиги
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator <<(BigInteger A, int n) { return A.ShiftLeft (n); }
		public static BigInteger operator >>(BigInteger A, int n) { return A.ShiftRight(n); }

		public BigInteger ShiftLeft(int n)
		{
			// проверить на нулевое число и сдвиг
			if (sign == 0) return Zero; if (n == 0) return this; 

			// проверить на отрицательный сдвиг
			if (n < 0) return ShiftRight(-n); 

			// выполнить сдвиг влево
			UInt32[] mag = Utils.ShiftLeft(magnitude, 0, n);

			// выернуть результат сдвига
			return new BigInteger(sign, mag, true);
		}

		public BigInteger ShiftRight(int n)
		{
			// проверить на нулевой и отрицательный сдвиг
			if (n == 0) return this; if (n < 0) return ShiftLeft(-n);

			// проверить на сдвиг, превышающий разрядность
			if (n >= BitLength) return (sign < 0) ? One.Negate() : Zero;

			// обработать отрицательное число
			if (sign < 0) return Not().ShiftRight(n).Not(); 

			// сделать копию массива
			UInt32[] mag = (UInt32[]) magnitude.Clone();

			// выполнить сдвиг вправо
			Utils.ShiftRight(mag, 0, n); return new BigInteger(1, mag, true);
		}
		///////////////////////////////////////////////////////////////////////
		// Изменение знака числа
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator -(BigInteger A) { return A.Negate(); }

		public BigInteger Abs   () { return (sign >= 0) ? this : Negate(); }
        public BigInteger Negate()
		{
			// изменить знак числа
			return (sign != 0) ? new BigInteger(-sign, magnitude, false) : this;
		}
		///////////////////////////////////////////////////////////////////////
		// Инкремент и декремент
		///////////////////////////////////////////////////////////////////////
		public BigInteger Increment()
		{
			// проверить на нулевое число
			if (sign == 0) return One;

			// скопировать модуль числа
			UInt32[] magCopy = (UInt32[])magnitude.Clone();

			// для положительного числа
			if (sign > 0)
			{
				// добавить единицу к модулю
				Utils.AddTo(magCopy, One.magnitude);

				// вернуть результат сложения
				return new BigInteger(1, magCopy, true);
			}
			else {
				// вычесть единицу от модуля
				Utils.SubtractFrom(magCopy, One.magnitude, 0);

				// вернуть результат вычитания
				return new BigInteger(-1, magCopy, true);
			}
		}
		public BigInteger Decrement()
		{
			// проверить на нулевое число
			if (sign == 0) return One.Negate();

			// скопировать модуль числа
			UInt32[] magCopy = (UInt32[])magnitude.Clone();

			// для положительного числа
			if (sign > 0)
			{
				// вычесть единицу от модуля
				Utils.SubtractFrom(magCopy, One.magnitude, 0);

				// вернуть результат вычитания
				return new BigInteger(1, magCopy, true);
			}
			else {
				// добавить единицу к модулю
				Utils.AddTo(magCopy, One.magnitude);

				// вернуть результат сложения
				return new BigInteger(-1, magCopy, true);
			}
		}
		///////////////////////////////////////////////////////////////////////
		// Сложение и вычитание
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator +(BigInteger A, BigInteger B) { return A.Add     (B); }
		public static BigInteger operator -(BigInteger A, BigInteger B) { return A.Subtract(B); }

		public BigInteger Add(BigInteger B)
		{
			// проверить на сложение с нулем
			if (sign == 0) return B; if (B.sign == 0) return this;

			// для чисел разного знака
			if (sign != B.sign)
			{
				// вычесть от первого числа второе
				if (B.sign < 0) return Subtract(B.Negate());

				// вычесть от второго числа первое
				else return B.Subtract(Negate());
			}
			// определить большее и меньшее число
			UInt32[] big = magnitude; UInt32[] small = B.magnitude;

			// определить большее и меньшее число
			if (magnitude.Length < B.magnitude.Length)
			{
				big = B.magnitude; small = magnitude;
			}
			// переразместить большее число
			UInt32[] bigCopy = new UInt32[big.Length + 1];

			// добавить к большему числу меньшее
			big.CopyTo(bigCopy, 1); Utils.AddTo(bigCopy, small);

			// вернуть результат сложения
			return new BigInteger(sign, bigCopy, true);
		}

		public BigInteger Subtract(BigInteger B)
		{
			// проверить на вычитание нуля
			if (B.sign == 0) return this; if (sign == 0) return B.Negate();

			// при несовпадении знаков перейти к сложению
			if (sign != B.sign) return Add(B.Negate());

			// сравнить абсолютные значения
			int compare = Utils.Compare(magnitude, 0, B.magnitude, 0);

			// при совпадении вернуть нуль
			if (compare == 0) return Zero;

			// определить большее и меньшее число
			UInt32[] big   = (compare < 0) ? B.magnitude : magnitude; 
			UInt32[] small = (compare > 0) ? B.magnitude : magnitude; 

			// скопировать большее число
			UInt32[] bigCopy = (UInt32[]) big.Clone();

			// вычесть меньшее число от большего
			Utils.SubtractFrom(bigCopy, small, 0); 
			
			// вернуть результат вычитания
			return new BigInteger(sign * compare, bigCopy, true);
		}
		///////////////////////////////////////////////////////////////////////
		// Умножение и возведение в степень
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator *(BigInteger A, BigInteger B) { return A.Multiply(B); }

		private BigInteger MultiplyImpl(BigInteger B)
		{
			// обработать умножение на нуль
			if (sign == 0 || B.sign == 0) return Zero;

			// обработать умножение на единицу
			if (B.Equals(One)) return this; if (Equals(One)) return B;

			// выделить массив для произведения
			UInt32[] magC = new UInt32[magnitude.Length + B.magnitude.Length];

			// обработать совпадающие операнды
			if (B == this) Utils.Square(magnitude, magC);

			// обработать несовпадающие операнды
			else Utils.Multiply(magnitude, B.magnitude, magC);

			// вернуть результат произведения
			return new BigInteger(sign * B.sign, magC, true);
		}
		public BigInteger Multiply(BigInteger B)
		{
#if !NO_NUMERICS
            // выполнить преобразованиие типа
            System.Numerics.BigInteger self  = ToNumericInteger(this);
            System.Numerics.BigInteger other = ToNumericInteger(B   );

            // выполнить умножение
            BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.Multiply(self, other)
            );  
#if NUMERICS_CHECK
            // проверить совпадение результата
            Debug.Assert(result == MultiplyImpl(B)); 
#endif             
            return result; 
#else
            // выполнить умножение
            return MultiplyImpl(B); 
#endif 
		}
		private BigInteger PowImpl(int exp)
		{
			// обработать нулевую степень
			Debug.Assert(exp >= 0); if (exp == 0) return One;

			// обработать нулевое значение и единицу
			if (sign == 0 || Equals(One)) return this;

			// задать начальные значения
			BigInteger result = One; BigInteger power = this;

			while (true)
			{
				// умножить на кратную 2 степень
				if ((exp & 1) != 0) result = result.Multiply(power);

				// проверить на завершение алгоритма
				exp >>= 1; if (exp == 0) break;

				// вычислить кратную 2 степень
				power = power.Multiply(power);
			}
			return result;
		}
		public BigInteger Pow(int exp)
		{
#if !NO_NUMERICS
            // выполнить преобразованиие типа
            System.Numerics.BigInteger self  = ToNumericInteger(this);

            // выполнить возведение в степень
            BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.Pow(self, exp)
            ); 
#if NUMERICS_CHECK
            // проверить совпадение результата
            Debug.Assert(result == PowImpl(exp)); 
#endif 
            return result; 
#else 
            // выполнить возведение в степень
            return PowImpl(exp); 
#endif 
		}
		///////////////////////////////////////////////////////////////////////
		// Частное и остаток от деления
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator /(BigInteger A, BigInteger B) { return A.Divide   (B); }
		public static BigInteger operator %(BigInteger A, BigInteger B) { return A.Remainder(B); }

		private BigInteger[] DivideAndRemainderImpl(BigInteger B)
		{
			// выделить массив для возвращаемых чисел
			Debug.Assert(B.sign != 0); BigInteger[] biggies = new BigInteger[2];

			// обработать нулевое число
			if (sign == 0) { biggies[0] = Zero; biggies[1] = Zero; return biggies; }

			// скопировать делимое
			UInt32[] remainder = (UInt32[])magnitude.Clone();

			// вычислить частное и остаток
			UInt32[] quotient = Utils.Divide(remainder, B.magnitude);

			// вернуть частное 
			biggies[0] = new BigInteger(sign * B.sign, quotient, true);

			// вернуть остаток
			biggies[1] = new BigInteger(sign, remainder, true);	return biggies;
		}
		public BigInteger[] DivideAndRemainder(BigInteger B)
		{
#if !NO_NUMERICS
			// выделить массив для возвращаемых чисел
			Debug.Assert(B.sign != 0); BigInteger[] biggies = new BigInteger[2];

            // выполнить преобразованиие типа
            System.Numerics.BigInteger self  = ToNumericInteger(this);
            System.Numerics.BigInteger other = ToNumericInteger(B   );

			// вычислить частное и остаток
            System.Numerics.BigInteger remainder; 
			System.Numerics.BigInteger quotient = 
                System.Numerics.BigInteger.DivRem(self, other, out remainder
            );
            // выполнить преобразованиие типа
            biggies[0] = FromNumericInteger(quotient ); 
            biggies[1] = FromNumericInteger(remainder); 
#if NUMERICS_CHECK
            // проверить совпадение результата
            Debug.Assert(biggies[0] == DivideImpl   (B)); 
            Debug.Assert(biggies[1] == RemainderImpl(B)); 
#endif 
            return biggies; 
#else 
            // вычислить частное и остаток
            return DivideAndRemainderImpl(B); 
#endif 
		}
		private BigInteger DivideImpl(BigInteger B)
		{
			// обработать нулевое число
			Debug.Assert(B.sign != 0); if (sign == 0) return Zero;

			// скопировать делимое
			UInt32[] remainder = (UInt32[])magnitude.Clone();

			// вычислить частное и остаток
			UInt32[] quotient = Utils.Divide(remainder, B.magnitude);

			// вернуть частное 
			return new BigInteger(sign * B.sign, quotient, true);
		}
		public BigInteger Divide(BigInteger B)
		{
#if !NO_NUMERICS
            // выполнить преобразованиие типа
            System.Numerics.BigInteger self  = ToNumericInteger(this);
            System.Numerics.BigInteger other = ToNumericInteger(B   );

			// вычислить частное 
            BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.Divide(self, other)
            );
#if NUMERICS_CHECK
            // проверить совпадение результата
            Debug.Assert(result == DivideImpl(B)); 
#endif 
            return result; 
#else
			// вернуть частное 
            return DivideImpl(B); 
#endif 
		}
		private BigInteger RemainderImpl(BigInteger B)
		{
			// обработать нулевое число
			Debug.Assert(B.sign != 0); if (sign == 0) return Zero;

			// для общего случая
			if (B.magnitude.Length > 1)
			{
				// сравнить делимое и делитель 
				if (Utils.Compare(magnitude, 0, B.magnitude, 0) < 0) return this;

				// скопировать делимое
				UInt32[] remainder = (UInt32[])magnitude.Clone();

				// вычислить остаток от деления
				Utils.Remainder(remainder, B.magnitude);

				// вернуть полученный результат
				return new BigInteger(sign, remainder, true);  
			}
			else {
				// обработать деление на единицу
				if (B.magnitude[0] == 1) return Zero;

				// вычислить остаток от деления
				UInt32 remainder = Utils.Remainder(magnitude, B.magnitude[0]);

				// проверить на нулевой результат
				if (remainder == 0) return Zero; 

				// вернуть полученный результат
				return new BigInteger(sign, new UInt32[] { remainder }, false);  
			}
        }
		public BigInteger Remainder(BigInteger B)
		{
#if !NO_NUMERICS
            // выполнить преобразованиие типа
            System.Numerics.BigInteger self  = ToNumericInteger(this);
            System.Numerics.BigInteger other = ToNumericInteger(B   );

			// вычислить остаток
			BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.Remainder(self, other)
            );
#if NUMERICS_CHECK
            // проверить совпадение результата
            Debug.Assert(result == RemainderImpl(B)); 
#endif 
            return result; 
#else 
			// вернуть остаток
            return RemainderImpl(B); 
#endif 
		}
 		///////////////////////////////////////////////////////////////////////
		// Модулярная арифметика
		///////////////////////////////////////////////////////////////////////
		public BigInteger Mod(BigInteger P)
		{
			// вычислить остаток от деления
			Debug.Assert(P.sign > 0); BigInteger remainder = Remainder(P);

			// вернуть остаток от деления
			return (remainder.sign >= 0) ? remainder : remainder.Add(P);
		}
		public BigInteger ModInverse(BigInteger P)
		{
			// проверить корректность данных
			Debug.Assert(P.sign > 0);   

			// выполнить расширенный алгоритм Евклида
			BigInteger[] result = Z.Ring.Instance.Euclid(Mod(P), P);

			// проверить корректность операции
			if (!result[0].Equals(One)) throw new ArithmeticException("GCD != 1");

			// вернуть обратный элемент
			return (result[1].sign >= 0) ? result[1] : result[1].Add(P);
		}
		private BigInteger ModPowOddImpl(BigInteger E, BigInteger P)
		{
			// проверить на единичный модуль
			if (P.Equals(BigInteger.One)) return BigInteger.Zero;

			// проверить на нулевое значение
			if (sign   == 0) return BigInteger.Zero;
			if (E.sign == 0) return BigInteger.One;

            // указать группу Монтгомери
            Fp.MontGroup group = new Fp.MontGroup(P); 

			// вычислить R = this * 2^{32n} mod P
			BigInteger R = ShiftLeft(32 * P.magnitude.Length).Mod(P);

			// вычислить R^E (mod P) по Монтгомери
			R = group.Power(R, E.Abs());

			// умножить на единицу по Монтгомери
			R = group.Product(R, One);

			// учесть знак экспоненты
			return E.sign > 0 ? R : R.ModInverse(P);
		}
		private BigInteger ModPowImpl(BigInteger E, BigInteger P)
		{
			// проверить корректность операнда
			Debug.Assert(sign >= 0 && CompareTo(P) < 0 && P.sign > 0); 

			// для нечетного модуля 
			if ((P.magnitude[P.magnitude.Length - 1] & 1) != 0) 
            {
                // возвести число в степень
                return ModPowOddImpl(E, P);
            }
			// проверить на нулевое значение
			if (sign   == 0) return BigInteger.Zero;
			if (E.sign == 0) return BigInteger.One;

			// выделить массив для результата 
			UInt32[] A = new UInt32[P.magnitude.Length];

			// задать начальные условия
			magnitude.CopyTo(A, A.Length - magnitude.Length);

			// выделить вспомогательный буфер
			UInt32[] T = new UInt32[P.magnitude.Length * 2];

			// прочитать старший разряд показателя степени
			UInt32 v = E.magnitude[0]; int bits = 0;

			// выдвинуть старший бит показателя степени 
			for (; (v & Int32.MinValue) == 0; v <<= 1, bits++) ; v <<= 1; bits++;

			// для всех разрядов показателя степени
			for (int i = 0; i < E.magnitude.Length; i++)
			{
				// прочитать очередной разряд показателя степени
				if (i > 0) { v = E.magnitude[i]; bits = 0; }

				// для всех битов показателя степени
				for (; v != 0; v <<= 1, bits++)
				{
					// возвести результат в квадрат по модулю
					Utils.Square(A, T); Utils.Remainder(T, P.magnitude);
					Array.Copy(T, T.Length - A.Length, A, 0, A.Length);

					// для единичного бита показателя степени
					if ((v & Int32.MinValue) != 0)
					{
						// умножить на исходное число по модулю
						Utils.Multiply(A, magnitude, T); Utils.Remainder(T, P.magnitude);
						Array.Copy(T, T.Length - A.Length, A, 0, A.Length);
					}
				}
				// для нулевых битов показателя степени
				for (; bits < 32; bits++)
				{
					// возвести результат в квадрат по модулю
					Utils.Square(A, T); Utils.Remainder(T, P.magnitude);
					Array.Copy(T, T.Length - A.Length, A, 0, A.Length);
				}
			}
			// избавиться от незначимых нулей
			BigInteger R = new BigInteger(1, A, true);

			// учесть знак экспоненты
			return E.sign > 0 ? R : R.ModInverse(P);
		}
		public BigInteger ModPow(BigInteger E, BigInteger P)
		{
			// проверить корректность операнда
			Debug.Assert(sign >= 0 && CompareTo(P) < 0 && P.sign > 0); 
#if !NO_NUMERICS
            // выполнить преобразованиие типа
            System.Numerics.BigInteger self    = ToNumericInteger(this);
            System.Numerics.BigInteger exp     = ToNumericInteger(E   );
            System.Numerics.BigInteger modulus = ToNumericInteger(P   );

			// выполнить возведение в степень
			BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.ModPow(self, exp, modulus)
            );
#if NUMERICS_CHECK
            // проверить совпадение результата
            Debug.Assert(result == ModPowImpl(E, P)); 
#endif 
            return result; 
#else 
			// выполнить возведение в степень
            return ModPowImpl(E, P); 
#endif 
		}
		///////////////////////////////////////////////////////////////////////
		// Проверка простоты чисел
		///////////////////////////////////////////////////////////////////////
		public bool IsProbablePrime(int certainty, Random rand)
		{
			// проверить необходимость проверки
			if (certainty <= 0) return true; BigInteger A = Abs();

			// четное число является простым, если равно 2
			if (!A.TestBit(0)) return A.Equals(Two);

			// единица не является простым числом
			if (A.Equals(One)) return false;

			// проверить число на простоту
			return A.CheckProbablePrime(certainty, rand);
		}
		private bool CheckProbablePrime(int certainty, Random rand)
		{
			// проверить на простоту небольшое число
			if (magnitude.Length == 1) return Utils.IsPrime(magnitude[0]);  

			// вычислить N - 1
			BigInteger N1 = Subtract(One); int S = 0; 

			// найти младший ненулевой разряд числа N-1
			for (int i = N1.magnitude.Length - 1; i >= 0; i--)
			{
				// пропустить нулевой разряд
				if (N1.magnitude[i] == 0) continue; UInt32 mask = 1; 

				// число битов за исключением найденного разряда
				int bitLength = 32 * (N1.magnitude.Length - 1 - i);

				// для всех битов ненулевого разряда
				for (int j = 0; j < 32; j++, mask <<= 1)
				{
					// найти младший ненулевой бит
					if ((N1.magnitude[i] & mask) != 0)
					{
						S = bitLength + j; break; 
					}
				}
				break; 
			}
			// вычислить R = (N - 1) / 2^S
			BigInteger R = N1.ShiftRight(S); int bits = BitLength; 

			// с указанной вероятностью
			for (BigInteger A; certainty > 0; certainty -= 2)
			{
				// сгенерировать случайное число
				do { A = new BigInteger(bits, rand); }

				// в диапазоне от 2 до N - 2 
				while (A.CompareTo(One) <= 0 || A.CompareTo(N1) >= 0);

				// вычислить Y = A^R mod N
				BigInteger Y = A.ModPow(R, this);

				// проверить на единицу
				if (Y.Equals(One)) continue; int j = 0;

				// пока Y не равно N-1
				while (!Y.Equals(N1))
				{
					// проверить на завершение
					if (++j == S) return false;

					// вычислить Y^{2^j} mod N
					Y = Y.ModPow(Two, this);

					// проверить на единицу
					if (Y.Equals(One)) return false;
				}
			}
			return true;
		}
	}
}
