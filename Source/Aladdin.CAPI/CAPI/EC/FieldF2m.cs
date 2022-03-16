using System;

namespace Aladdin.CAPI.EC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Конечное поле F_{2^m}
    ///////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class FieldF2m : Field, IEquatable<FieldF2m> 
    {
        // математическое поле и образующий многочлен
        private Math.F2m.Field field; private Math.BigInteger polynom;

        // конструктор
        public FieldF2m(Math.F2m.Field field) 
        { 
            // сохранить переданные параметры
            this.field = field; this.polynom = null; 

            // для поля с образующим многочленом
            if (field is Math.F2m.PolyField)
            {
                // выполнить преобразование типа
                Math.F2m.PolyField polyField = (Math.F2m.PolyField)field; 

                // сохранить образующий многочлен
                polynom = polyField.Polynom.ToBigInteger(); 
            }
        }
        // конструктор
        public FieldF2m(int m, Math.BigInteger polynom) 
        {
            // проверить корректность параметров
            if (m <= 0) throw new ArgumentException(); this.polynom = polynom; 
        
            // проверить корректность параметров
            if (!polynom.TestBit(0) || !polynom.TestBit(m)) 
            {
                // при ошибке выбросить исключение
                throw new ArgumentException();
            }
            // указать используемое поле
            field = new Math.F2m.PolyField(new Math.Polynom(polynom)); 
        }
        // конструктор 
        public FieldF2m(int m) 
        {
            // проверить корректность параметров
            if (m <= 0) throw new ArgumentException();
        
            // указать используемое поле
            field = new Math.F2m.NormField(m); polynom = null; 
        }
        // разрядность поля
        public override int FieldSize { get { return field.M; }}
        public          int M         { get { return field.M; }}

        // образующий многочлен
        public Math.BigInteger ReductionPolynomial { get { return polynom; }}
    
        // сравнить объекты
        public bool Equals(FieldF2m obj) 
        {
            // проверить совпадение ссылок
            if (this == obj) return true; if (obj == null) return false; 

            // сравнить объекты
            if (polynom == null) return (M == obj.M && obj.polynom == null); 

            // сравнить объекты
            return (M == obj.M && polynom.Equals(obj.polynom)); 
        }
        // сравнить объекты
        public override bool Equals(object obj) 
        {
            // проверить совпадение ссылок
            if (this == obj)  return true;
        
            // проверить тип объекта
            if (!(obj is FieldF2m)) return false; 
        
            // сравнить объекты
            return Equals((FieldF2m)obj);
        }
        // хэш-код объекта
        public override int GetHashCode() 
        { 
            // вычислить хэш-код объекта
            if (polynom == null) return M << 5; 
        
            // вычислить хэш-код объекта
            return polynom.GetHashCode() + (M << 5); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Операции аддитивной группы
        ///////////////////////////////////////////////////////////////////////////

        // признак нулевого элемента
        public override bool IsZero(Math.BigInteger P) { return P.Signum == 0; }
        // нулевой элемент
        public override Math.BigInteger Zero { get { return Math.BigInteger.Zero; }}
    
        // противоположный элемент
        public override Math.BigInteger Negate(Math.BigInteger P) 
        { 
            // выполнить преобразование типа
            Math.Vector element = new Math.Vector(P, M); 
        
            // вычислить противоположный элемент
            return field.Negate(element).ToBigInteger(); 
        } 
        // удвоенный элемент
        public override Math.BigInteger Twice(Math.BigInteger P) 
        { 
            // выполнить преобразование типа
            Math.Vector element = new Math.Vector(P, M); 
        
            // вычислить удвоенный элемент
            return field.Twice(element).ToBigInteger(); 
        } 
        // сложение элементов
        public override Math.BigInteger Add(Math.BigInteger P, Math.BigInteger Q)
        {
            // выполнить преобразование типа
            Math.Vector elementP = new Math.Vector(P, M); 
            Math.Vector elementQ = new Math.Vector(Q, M); 
        
            // выполнить сложение элементов
            return field.Add(elementP, elementQ).ToBigInteger(); 
        }
        // вычитание элементов
        public override Math.BigInteger Subtract(Math.BigInteger P, Math.BigInteger Q)
        {
            // выполнить преобразование типа
            Math.Vector elementP = new Math.Vector(P, M); 
            Math.Vector elementQ = new Math.Vector(Q, M); 
        
            // выполнить вычитание элементов
            return field.Subtract(elementP, elementQ).ToBigInteger(); 
        }
        // вычисление кратного элемента
        public override Math.BigInteger Multiply(Math.BigInteger P, Math.BigInteger e)
        {
            // выполнить преобразование типа
            Math.Vector element = new Math.Vector(P, M); 
        
            // вычислить кратный элемент
            return field.Multiply(element, e).ToBigInteger(); 
        }
        // сумма кратных элементов
        public override Math.BigInteger MultiplySum(
            Math.BigInteger P, Math.BigInteger a, Math.BigInteger Q, Math.BigInteger b)
        {
            // выполнить преобразование типа
            Math.Vector elementP = new Math.Vector(P, M); 
            Math.Vector elementQ = new Math.Vector(Q, M); 
        
            // вычислить сумму кратных элементов
            return field.MultiplySum(elementP, a, elementQ, b).ToBigInteger(); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Операции мультипликативной группы
        ///////////////////////////////////////////////////////////////////////////
    
        // признак единичного элемента
        public override bool IsOne(Math.BigInteger P) 
        { 
            // признак единичного элемента
            return field.IsOne(new Math.Vector(P, M)); 
        } 
        // единичный элемент
        public override Math.BigInteger One { get { return field.One.ToBigInteger(); }}
    
        // обратный элемент
        public override Math.BigInteger Invert(Math.BigInteger P) 
        { 
            // выполнить преобразование типа
            Math.Vector element = new Math.Vector(P, M); 
        
            // вычислить обратный элемент
            return field.Invert(element).ToBigInteger(); 
        } 
        // возведенный в квадрат элемент
        public override Math.BigInteger Sqr(Math.BigInteger P) 
        { 
            // выполнить преобразование типа
            Math.Vector element = new Math.Vector(P, M); 
        
            // вычислить возведенный в квадрат элемент
            return field.Sqr(element).ToBigInteger(); 
        } 
        // умножение элементов
        public override Math.BigInteger Product(Math.BigInteger P, Math.BigInteger Q)
        {
            // выполнить преобразование типа
            Math.Vector elementP = new Math.Vector(P, M); 
            Math.Vector elementQ = new Math.Vector(Q, M); 
        
            // выполнить умножение элементов
            return field.Product(elementP, elementQ).ToBigInteger(); 
        }
        // деление элементов
        public override Math.BigInteger Divide(Math.BigInteger P, Math.BigInteger Q)
        {
            // выполнить преобразование типа
            Math.Vector elementP = new Math.Vector(P, M); 
            Math.Vector elementQ = new Math.Vector(Q, M); 
        
            // выполнить деление элементов
            return field.Divide(elementP, elementQ).ToBigInteger(); 
        }
        // возведение в степень элемента
        public override Math.BigInteger Power(Math.BigInteger P, Math.BigInteger e)
        {
            // выполнить преобразование типа
            Math.Vector element = new Math.Vector(P, M); 
        
            // выполнить возведение в степень
            return field.Power(element, e).ToBigInteger(); 
        }
        // умножение возведенных в степень элементов
        public override Math.BigInteger PowerProduct(
            Math.BigInteger P, Math.BigInteger a, Math.BigInteger Q, Math.BigInteger b)
        {
            // выполнить преобразование типа
            Math.Vector elementP = new Math.Vector(P, M); 
            Math.Vector elementQ = new Math.Vector(Q, M); 
        
            // выполнить умножение возведенных в степень элементов
            return field.PowerProduct(elementP, a, elementQ, b).ToBigInteger(); 
        }
    }
}
