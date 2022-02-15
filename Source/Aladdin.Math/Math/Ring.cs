using System; 

namespace Aladdin.Math 
{
    ////////////////////////////////////////////////////////////////////////////
    // Интерфейс кольца
    ////////////////////////////////////////////////////////////////////////////
    public abstract class Ring<E> : GroupAdd<E>, IRing<E>
    {
        // признак единичного элемента
        public virtual bool IsOne(E a) { return a.Equals(One); }
    
        // единичный элемент
        public abstract E One { get; }
    
        // умножение элементов
        public abstract E Product(E a, E b); 
    
        // вычисление частного и остатка
        public abstract E Divide   (E a, E b); 
        public abstract E Remainder(E a, E b); 

        // вычисление частного и остатка
        public virtual E[] DivideAndRemainder(E a, E b)
        {
            // вычислить частное и остаток
            return new E[] { Divide(a, b), Remainder(a, b) }; 
        }
        // возведение в квадрат
        public virtual E Sqr(E a) { return Product(a, a); } 
    
        // вычисление степени элемента
        public virtual E Power(E a, BigInteger e)
        {
            // проверить необходимость вычислений
            if (IsOne(a) || e.Signum == 0) return One; E r = a; 

            // обработать отрицательную степень
            if (e.Signum < 0) throw new ArgumentException(); 
        
  		    // для всех битов
            for (int i = e.BitLength - 2; i >= 0; i--)
            {
                // выполнить вычисления
                r = Sqr(r); if (e.TestBit(i)) r = Product(r, a);
            }
            return r; 
        }
        // произведение степеней элементов 
        public virtual E PowerProduct(E P, BigInteger a, E Q, BigInteger b)
        {
            // проверить корректность данных
            if (a.Signum < 0 || b.Signum < 0) throw new ArgumentException(); 
        
            // определить разрядность большего сомножителя
		    int bits = System.Math.Max(a.BitLength, b.BitLength);

		    // задать начальные условия
		    E R = One; E Z = Product(P, Q);

		    // для всех битов
		    for (int i = bits - 1; i >= 0; i--)
		    {
                // извлечь значение битов
                bool aBit = a.TestBit(i); 
                bool bBit = b.TestBit(i); R = Sqr(R);
            
                // выполнить вычисления
                if (aBit) R = Product(R, bBit ? Z : P); 
            
                // выполнить вычисления
                else if (bBit) R = Product(R, Q);
		    }
		    return R;
        }
        ///////////////////////////////////////////////////////////////////////
        // Наибольший общий делитель
        ///////////////////////////////////////////////////////////////////////
        public virtual E GCD(E A, E B)
        {
		    // обработать нулевые числа
		    if (IsZero(B)) return A; if (IsZero(A)) return B;

            // задать начальные условия для алгоритма
		    E divident = A; E divisor = B;

		    // выполнить алгоритм Евклида
		    while (!IsZero(divisor))
		    {
                // вычислить остаток от деления
                E remainder = Remainder(divident, divisor);

                // переустановить делимое и делитель
                divident = divisor; divisor = remainder;
		    }
		    // вернуть последний остаток
		    return divident;
        }
        ///////////////////////////////////////////////////////////////////////
        // Расширенный алгоритм Евклида
        ///////////////////////////////////////////////////////////////////////
        public virtual E[] Euclid(E A, E B)
        {
		    // создать результирующий массив
            E[] result = new E[3]; 

            // инвариант U1 * A + V1 * B = Ai
		    // инвариант U2 * A + V2 * B = Bi
		    E Ai = A; E U1 = One;  E V1 = Zero;
		    E Bi = B; E U2 = Zero; E V2 = One;

		    // выполнять пока делитель больше нуля
		    for (E[] Q; !IsZero(Bi); Ai = Bi, Bi = Q[1])
		    {
                // вычислить частное и остаток от деления
                Q = DivideAndRemainder(Ai, Bi);

                // пересчитать коэффициенты инварианта
                E TU = Subtract(U1, Product(U2, Q[0]));
                E TV = Subtract(V1, Product(V2, Q[0]));

                // переустановить коэффициенты
                U1 = U2; V1 = V2; U2 = TU; V2 = TV;
            }
            // вернуть результат
            result[0] = Ai; result[1] = U1; result[2] = V1; return result; 
        }  
    }
}