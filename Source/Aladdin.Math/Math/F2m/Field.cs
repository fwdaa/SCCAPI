using System; 

namespace Aladdin.Math.F2m
{
    ///////////////////////////////////////////////////////////////////////////
    // Поле многочленов (F_{2^m})
    ///////////////////////////////////////////////////////////////////////////
    public abstract class Field : Math.Field<Vector>
    {
        // нулевой элемент
        private Vector zero; 

        // конструктор
        public Field(int m) { zero = Vector.Zeros(m); }
    
        // размерность поля
        public override int Dimension { get { return M; }}

        // вернуть размерность поля 
        public int M { get { return zero.M; }}
    
        ///////////////////////////////////////////////////////////////////////
        // Операции аддитивной группы
        ///////////////////////////////////////////////////////////////////////
        public override Vector Zero { get { return zero; }}

        public override Vector Negate(Vector a) { return a;    }
        public override Vector Twice (Vector a) { return Zero; } 
    
        public override Vector Add     (Vector a, Vector b) { return a.Add(b); }
        public override Vector Subtract(Vector a, Vector b) { return a.Add(b); }

        // вычисление кратного элемента
        public override Vector Multiply(Vector a, BigInteger e) 
        { 
            // вычисление кратного элемента
            return e.TestBit(0) ? a : Zero; 
        }
        // вычисление квадратного корня
        public virtual Vector Sqrt(Vector a) { Vector r = a; 
        
            // вычислить a^{2^{m-1}}
            for (int i = 0; i < M - 1; i++) r = Sqr(r); return r; 
        } 
        ///////////////////////////////////////////////////////////////////////
        // Сгенерировать случайное число
        ///////////////////////////////////////////////////////////////////////
        public Vector Generate(Random random)
        {
            // сгенерировать вектор
            return new Vector(random, M); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Специальные функции
        ///////////////////////////////////////////////////////////////////////
        public abstract int Trace(Vector a);  

        // корень z уравнения z^2 + z = beta (второй корень = z + 1)
        public abstract Vector QuadraticRoot(Vector beta);  
    }
}