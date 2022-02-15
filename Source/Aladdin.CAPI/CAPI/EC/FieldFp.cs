using System;

namespace Aladdin.CAPI.EC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Конечное поле Fp
    ///////////////////////////////////////////////////////////////////////////////
    public class FieldFp : Field, IEquatable<FieldFp>
    {
        // математическое поле
        private Math.Fp.Field field; 
    
        // конструктор
        public FieldFp(Math.Fp.Field field) { this.field = field; }

        // конструктор
        public FieldFp(Math.BigInteger p) 
        {
            // сохранить переданные параметры
            field = new Math.Fp.Field(p); 
        }
        // разрядность поля
        public override int FieldSize { get { return P.BitLength; }}

        // значение модуля
        public Math.BigInteger P { get { return field.P; }}

        // сравнить объекты
        public bool Equals(FieldFp obj) 
        {
            // проверить совпадение ссылок
            if (this == obj) return true; 
        
            // сравнить модули
            return (obj != null) ? P.Equals(obj.P) : false;
        }
        // сравнить объекты
        public override bool Equals(object obj) 
        {
            // проверить совпадение ссылок
            if (this == obj)  return true;
        
            // проверить тип объекта
            if (!(obj is FieldFp)) return false; 
        
            // сравнить объекты
            return Equals((FieldFp)obj);
        }
        // хэш-код объекта
        public override int GetHashCode() { return P.GetHashCode(); }

        ///////////////////////////////////////////////////////////////////////////
        // Операции аддитивной группы
        ///////////////////////////////////////////////////////////////////////////

        // признак нулевого элемента
        public override bool IsZero(Math.BigInteger P) { return P.Signum == 0; }
        // нулевой элемент
        public override Math.BigInteger Zero { get { return Math.BigInteger.Zero; }}
    
        // противоположный и удвоенный элемент
        public override Math.BigInteger Negate(Math.BigInteger P) { return field.Negate(P); } 
        public override Math.BigInteger Twice (Math.BigInteger P) { return field.Twice (P); } 
    
        // сложение элементов
        public override Math.BigInteger Add(Math.BigInteger P, Math.BigInteger Q)
        {
            // выполнить сложение элементов
            return field.Add(P, Q); 
        }
        // вычитание элементов
        public override Math.BigInteger Subtract(Math.BigInteger P, Math.BigInteger Q)
        {
            // выполнить вычитание элементов
            return field.Subtract(P, Q); 
        }
        // вычисление кратного элемента
        public override Math.BigInteger Multiply(Math.BigInteger P, Math.BigInteger e)
        {
            // вычислить кратный элемент
            return field.Multiply(P, e); 
        }
        // сумма кратных элементов
        public override Math.BigInteger MultiplySum(Math.BigInteger P, 
            Math.BigInteger a, Math.BigInteger Q, Math.BigInteger b)
        {
            // вычислить сумму кратных элементов
            return field.MultiplySum(P, a, Q, b); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Операции мультипликативной группы
        ///////////////////////////////////////////////////////////////////////////
    
        // признак единичного элемента
        public override bool IsOne(Math.BigInteger P) { return field.IsOne(P); } 
        // единичный элемент
        public override Math.BigInteger One { get { return Math.BigInteger.One; }}
    
        // обратный и возведенный в квадрат элемент
        public override Math.BigInteger Invert(Math.BigInteger P) { return field.Invert(P); } 
        public override Math.BigInteger Sqr   (Math.BigInteger P) { return field.Sqr   (P); } 
    
        // умножение элементов
        public override Math.BigInteger Product(Math.BigInteger P, Math.BigInteger Q)
        {
            // выполнить умножение элементов
            return field.Product(P, Q); 
        }
        // деление элементов
        public override Math.BigInteger Divide(Math.BigInteger P, Math.BigInteger Q)
        {
            // вычислить деление элементов
            return field.Divide(P, Q); 
        }
        // возведение в степень элемента
        public override Math.BigInteger Power(Math.BigInteger P, Math.BigInteger e)
        {
            // выполнить возведение в степень
            return field.Power(P, e); 
        }
        // умножение возведенных в степень элементов
        public override Math.BigInteger PowerProduct(Math.BigInteger P, 
            Math.BigInteger a, Math.BigInteger Q, Math.BigInteger b)
        {
            // выполнить умножение возведенных в степень элементов
            return field.PowerProduct(P, a, Q, b); 
        }
    }
}
