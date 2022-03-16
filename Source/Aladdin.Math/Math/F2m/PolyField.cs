using System; 

namespace Aladdin.Math.F2m
{
    ///////////////////////////////////////////////////////////////////////////
    // Поле многочленов (F_{2^m}) в полиномиальном базисе
    // Многочлен a(x) = a_0 x^{m-1} + ... + a_{m-2} x + a_{m-1}
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class PolyField : Field, IEquatable<PolyField>
    {
        // образующий многочлен и единичный элемент
        private Polynom polynom; private Vector one;

        // конструктор
        public PolyField(Polynom polynom) : base(polynom.BitLength - 1)
        { 
            // сохранить переданные параметры
            this.polynom = polynom; 
        
            // создать единичный элемент
            VectorBuilder builder = new VectorBuilder(M); 
        
            // указать единичный элементы
            builder[M - 1] = 1; one = builder.ToVector(); 
        }
        // вернуть многочлен поля
        public Polynom Polynom { get { return polynom; }}

        // сравнение полей
        public virtual bool Equals(PolyField other)
        {
            // сравнение полей
		    return polynom.Equals(other.polynom);
        }
        // сравнение полей
        public override bool Equals(object other)
        {
            // проверить совпадение экземпляров
		    if (other == this) return true;

            // проверить тип элемента
		    if (!(other is PolyField)) return false;

		    // сравнить значения элементов
		    return Equals((PolyField)other);
        }
        // получить хэш-код объекта
        public override int GetHashCode() { return polynom.GetHashCode(); }

        //////////////////////////////////////////////////////////////////////
        // Операции мультипликативной группы
        ///////////////////////////////////////////////////////////////////////
        public override Vector One { get { return one; }}

        public override Vector Invert(Vector a)
        {
            // выполнить расширенный алгоритм Евклида
            Polynom[] euclid = PZ.Ring.Instance.Euclid(a.ToPolynom(), polynom); 
        
            // проверить наличие обратного элемента
            Polynom U = euclid[1]; if (!euclid[0].Equals(Polynom.One))
            {
                // при ошибке выбросить исключение
                throw new ArgumentException("GCD != 1"); 
            }
		    // выполнить дополнительное приведение
            if (U.BitLength == polynom.BitLength) U = U.Add(polynom);
        
            // вернуть результат
            return U.ToVector(M); 
        }
        public override Vector Product(Vector a, Vector b)
        {
            // выполнить преобразование типа
            Polynom polynomA = a.ToPolynom(); Polynom polynomB = b.ToPolynom(); 
        
		    // выполнить умножение многочленов
		    return polynomA.Product(polynomB).Remainder(polynom).ToVector(M);
        }
        //////////////////////////////////////////////////////////////////////
        // Специальные функции
        ///////////////////////////////////////////////////////////////////////
        public override int Trace(Vector a) { Vector T = a; 
        
            // выполнить вычисления
            for (int i = 1; i < M; i++) T = Add(Sqr(T), a); return T[M - 1]; 
        }
        public Vector HalfTrace(Vector a) { Vector T = a; 
        
            // проверить корректность параметров
            if ((M & 1) == 0) throw new ArgumentException(); 
    
            // выполнить ычисления
            for (int i = 1; i <= (M - 1) / 2; i++) T = Add(Sqr(Sqr(T)), a); return T; 
        }
        //////////////////////////////////////////////////////////////////////
        // Корень z квадратного уравнения z^2 + z = beta 
        // Генератор случайных данных используется при четном m
        //////////////////////////////////////////////////////////////////////
        public override Vector QuadraticRoot(Vector beta)
        { 
            // обработать тривиальный случай
            if (IsZero(beta)) return beta; if ((M & 1) != 0)
            {
                // выполнить вычисления
                Vector z = HalfTrace(beta); Vector gamma = Add(Sqr(z), z);
            
                // вернуть квадратный корень
                return (gamma.Equals(beta)) ? z : null; 
            }
            else { 
                // указать генератор слуайных данных
                Random random = new Random(); Vector z;
                do {
                    // сгенерировать случайный элемент
                    Vector tau = Generate(random); Vector w = beta; z = Zero; 

                    // требуемое число раз
                    for (int i = 1; i < M; i++)
                    {
                        // выполнить вычисления
                        z = Add(Sqr(z), Product(Sqr(w), tau));

                        // выполнить вычисления
                        w = Add(Sqr(w), beta); 
                    }
                    // проверить наличие корней
                    if (!IsZero(w)) return null; 
                }
                // проверить условие 
                while (IsZero(Add(Sqr(z), z))); return z; 
            }
        }
    }
}