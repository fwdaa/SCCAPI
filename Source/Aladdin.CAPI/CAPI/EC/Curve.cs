using System;
using System.IO;

namespace Aladdin.CAPI.EC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Эллиптипческая кривая
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class Curve : IEquatable<Curve>
    {
        // конечное поле и параметры генерации
        private Field field; private byte[] seed;
        // коэффициенты уравнения
        private Math.BigInteger a; private Math.BigInteger b;
    
        // конструктор
        protected Curve(Field field, Math.BigInteger a, Math.BigInteger b) 
        
            // сохранить переданные параметры
            : this(field, a, b, null) {}
        
        // конструктор
        protected Curve(Field field, Math.BigInteger a, Math.BigInteger b, byte[] seed) 
        {
            // сохранить переданные параметры
            this.field = field; this.a = a; this.b = b;
        
            // сохранить переданные параметры
            this.seed = (seed != null) ? (byte[])seed.Clone() : null; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Свойства эллиптической кривой
        ///////////////////////////////////////////////////////////////////////

        // конечное поле
        public Field Field { get { return field; }}

        // коэффициенты уравнения
        public Math.BigInteger A { get { return a; }}
        public Math.BigInteger B { get { return b; }}

        // параметры генерации
        public byte[] Seed { get { return (seed != null) ? (byte[])seed.Clone() : null; }}

        // признак принадлежности эллиптической кривой
        public abstract bool IsPoint(Point P); 

        // создать точку на эллиптической кривой
        protected abstract Point CreatePoint(Math.BigInteger x, Math.BigInteger y); 

        ///////////////////////////////////////////////////////////////////////
        // Сравнение объектов
        ///////////////////////////////////////////////////////////////////////
        public bool Equals(Curve obj) 
        {
            // проверить совпадение ссылок
            if (this == obj) return true; if (obj == null) return false; 
        
            // сравнить используемые поля 
            if (!field.Equals(obj.Field)) return false; 
        
            // сравнить коэффициенты уравнения
            return (a.Equals(obj.A) && b.Equals(obj.B)); 
        }
        // сравнить объекты
        public override bool Equals(object obj) 
        {
            // проверить совпадение ссылок
            if (this == obj)  return true;
        
            // проверить тип объекта
            if (!(obj is Curve)) return false; 
        
            // сравнить объекты
            return Equals((Curve)obj);
        }
        // хэш-код объекта
        public override int GetHashCode() 
        { 
            // вычислить хэш-код объекта
            int hashCode = (field.GetHashCode() << 6); 

            // вычислить хэш-код объекта
            return hashCode + (a.GetHashCode() << 4) + (b.GetHashCode() << 2);
        }
        ///////////////////////////////////////////////////////////////////////////
        // Операции аддитивной группы
        ///////////////////////////////////////////////////////////////////////////

        // нулевой элемент
        public Point Zero { get { return Point.Infinity; }}
        // признак нулевого элемента
        public bool IsZero(Point P) { return Object.ReferenceEquals(P, Zero); }

        // противоположный элемент
        public abstract Point Negate(Point P); 

        // сложение и вычитание элементов
        public abstract Point Add     (Point P, Point Q);
        public abstract Point Subtract(Point P, Point Q); 
        // удвоение элемента
        public abstract Point Twice(Point P); 

        // вычисление кратного элемента 
        public abstract Point Multiply(Point P, Math.BigInteger e); 
        // сумма кратных элементов
        public abstract Point MultiplySum(
            Point P, Math.BigInteger a, Point Q, Math.BigInteger b
        ); 
        ///////////////////////////////////////////////////////////////////////////
        // Кодирование точек эллиптической кривой
        ///////////////////////////////////////////////////////////////////////////
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // закодировать точку
        public byte[] Encode(Point P, Encoding encoding)
        {
            // проверить на бесконечность
            if (IsZero(P)) return new byte[] { 0x00 }; 
        
            // определить размер закодированных представлений
            int cb = (Field.FieldSize + 7) / 8; switch (encoding)
            {
            case Encoding.Uncompressed: case Encoding.Default: 
            {
                // закодировать координаты X и Y
                byte[] X1 = Math.Convert.FromBigInteger(P.X, Endian, cb); 
                byte[] Y1 = Math.Convert.FromBigInteger(P.Y, Endian, cb);
            
                // вернуть закодированное представление
                return Arrays.Concat(new byte[] { 0x04 }, X1, Y1); 
            }
            case Encoding.Compressed: 
            {
                // вычислить дополнительный бит
                byte[] PC = new byte[] { Compress(P) == 0 ? (byte)0x02 : (byte)0x03 }; 
            
                // вернуть закодированное представление
                return Arrays.Concat(PC, Math.Convert.FromBigInteger(P.X, Endian, cb)); 
            }
            case Encoding.Hybrid: 
            {
                // вычислить дополнительный бит
                byte[] PC = new byte[] { Compress(P) == 0 ? (byte)0x06 : (byte)0x07 }; 
            
                // закодировать координаты X и Y
                byte[] X1 = Math.Convert.FromBigInteger(P.X, Endian, cb); 
                byte[] Y1 = Math.Convert.FromBigInteger(P.Y, Endian, cb);

                // вернуть закодированное представление
                return Arrays.Concat(PC, X1, Y1); 
            }}
            return null; 
        }
        // раскодировать точку
        public Point Decode(byte[] encoded) { return Decode(encoded, Encoding.Default); }

        // раскодировать точку
        public Point Decode(byte[] encoded, Encoding encoding)
        {
            // проверить корректность данных
            if (encoded.Length == 0) throw new InvalidDataException(); switch (encoded[0])
            {
            case 0x00:
            {
                // вернуть бесконечно удаленную точку
                if (encoded.Length != 1) throw new InvalidDataException(); return Zero; 
            }
            case 0x02: case 0x03:
            {
                // проверить тип кодирования
                if (encoding != Encoding.Default && encoding != Encoding.Compressed)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                // раскодировать координату X
                Math.BigInteger X = Math.Convert.ToBigInteger(encoded, 1, encoded.Length - 1, Endian); 
                 
                // создать точку эллиптической кривой
                return Decompress(X, encoded[0] - 0x02); 
            }
            case 0x04:
            {
                // проверить тип кодирования
                if (encoding != Encoding.Default && encoding != Encoding.Uncompressed)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                // проверить корректность размера
                if ((encoded.Length & 1) == 0) throw new InvalidDataException(); 
            
                // вычислить размер каждой координаты
                int length = (encoded.Length - 1) / 2; 
            
                // раскодировать координаты
                Math.BigInteger X = Math.Convert.ToBigInteger(encoded, 1         , length, Endian); 
                Math.BigInteger Y = Math.Convert.ToBigInteger(encoded, 1 + length, length, Endian); 
            
                // создать точку эллиптической кривой
                return CreatePoint(X, Y); 
            }
            case 0x06: case 0x07:
            {
                // проверить тип кодирования
                if (encoding != Encoding.Default && encoding != Encoding.Hybrid)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                // проверить корректность размера
                if ((encoded.Length & 1) == 0) throw new InvalidDataException(); 
            
                // вычислить размер каждой координаты
                int length = (encoded.Length - 1) / 2; 
            
                // раскодировать координаты
                Math.BigInteger X = Math.Convert.ToBigInteger(encoded, 1         , length, Endian); 
                Math.BigInteger Y = Math.Convert.ToBigInteger(encoded, 1 + length, length, Endian); 
            
                // создать точку эллиптической кривой
                Point P = CreatePoint(X, Y); 
            
                // проверить корректность данных
                if (Compress(P) != encoded[0] - 0x06) throw new InvalidDataException(); return P;  
            }}
            throw new InvalidDataException(); 
        }
        // вычислить дополнительный бит при сжатии
        protected abstract int Compress(Point P); 
    
        // вычислить точку кривой при расжатии
        protected abstract Point Decompress(Math.BigInteger x, int y0); 
    }
}
