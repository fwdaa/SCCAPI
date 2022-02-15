using System; 
using System.IO; 

namespace Aladdin.CAPI.ANSI.X962.F2m
{
    ////////////////////////////////////////////////////////////////////////////////
    // Фабрика кодирования кючей
    ////////////////////////////////////////////////////////////////////////////////
    public class KeyFactory : X962.KeyFactory
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // конструктор
        public KeyFactory(string keyOID) : base(keyOID) {} 
    
        // закодировать параметры
        public override ASN1.IEncodable EncodeParameters(
            CAPI.IParameters parameters, EC.Encoding encoding, bool useOID) 
        {
            // при указании идентификатора 
            if (parameters is INamedParameters && useOID)
            {
                // закодировать идентификатор параметров
                return new ASN1.ObjectIdentifier(((INamedParameters)parameters).Oid); 
            }
            // преобразовать тип параметров
            X962.IParameters ecParameters = (X962.IParameters)parameters; 
            
            // получить описание эллиптической кривой
            EC.CurveF2m ec = (EC.CurveF2m)ecParameters.Curve; int m = ec.Field.M; 
        
            // указать идентификатор типа поля
            ASN1.ObjectIdentifier fieldType = new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_c2_field); 
            
            // инициализировать переменные
            string oid = null; ASN1.IEncodable fieldParameters = null; int cb = (m + 7) / 8;  
            
            // в зависимости от типа поля
            if (ec.Field.ReductionPolynomial == null)
            {
                // указать отсутствие параметров
                oid = ASN1.ANSI.OID.x962_c2_basis_gn; fieldParameters = ASN1.Null.Instance;
            }
            else {
                // получить образующий многочлен
                Math.BigInteger polynom = ec.Field.ReductionPolynomial; 
                
                // создать список установленных степеней многочлена
                ASN1.Integer[] k = new ASN1.Integer[3]; int count = 0; 
                
                // для всех коэффициентов многочлена
                for (int i = 1; i < m; i++)
                {
                    // проверить наличие степени
                    if (!polynom.TestBit(i)) continue; 
                    
                    // проверить корректность степени
                    if (count >= k.Length) throw new ArgumentException(); 
                    
                    // сохранить индекс степени
                    k[count] = new ASN1.Integer(i); count++; 
                }
                // закодировать параметры
                if (count == 1) { oid = ASN1.ANSI.OID.x962_c2_basis_tp; fieldParameters = k[0]; } 
                
                // для пентаномов
                else if (count == 3) { oid = ASN1.ANSI.OID.x962_c2_basis_pp;
               
                    // закодировать параметры
                    fieldParameters = new ASN1.ANSI.X962.Pentanomial(k[0], k[1], k[2]); 
                }
            }
            // при ошибке выбросить исключение
            if (oid == null) throw new ArgumentException(); 
            
            // закодировать характеристики поля
            ASN1.ANSI.X962.CharacteristicTwo characteristics = new ASN1.ANSI.X962.CharacteristicTwo(
                new ASN1.Integer(m), new ASN1.ObjectIdentifier(oid), fieldParameters
            ); 
            // закодировать параметры поля
            ASN1.ANSI.X962.FieldID fieldID = new ASN1.ANSI.X962.FieldID(fieldType, characteristics); 
            
            // закодировать параметры a и b кривой
            ASN1.OctetString encodedA = new ASN1.OctetString(Math.Convert.FromBigInteger(ec.A, Endian, cb));
            ASN1.OctetString encodedB = new ASN1.OctetString(Math.Convert.FromBigInteger(ec.B, Endian, cb));
            
            // при наличии параметров генерации
            ASN1.BitString encodedSeed = null; if (ec.Seed != null) 
            {
                // закодировать параметры генерации
                encodedSeed = new ASN1.BitString(ec.Seed);
            } 
            // закодировать базовую точку эллиптической кривой
            ASN1.OctetString encodedG = new ASN1.OctetString(ec.Encode(ecParameters.Generator, encoding));
            
            // закодировать порядок базовой точки
            ASN1.Integer encodedN = new ASN1.Integer(ecParameters.Order); 
            ASN1.Integer encodedH = new ASN1.Integer(ecParameters.Cofactor); 
            
            // закодировать параметры эллиптической кривой
            ASN1.ANSI.X962.Curve encodedEC = new ASN1.ANSI.X962.Curve(encodedA, encodedB, encodedSeed); 
            
            // закодировать параметры в целом
            return new ASN1.ANSI.X962.SpecifiedECDomain(new ASN1.Integer(1), 
                fieldID, encodedEC, encodedG, encodedN, encodedH, ecParameters.Hash
            ); 
        }
        public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encoded)
        {
            // раскодировать параметры
            encoded = new ASN1.ANSI.X962.ECDomainParameters().Decode(encoded); 
        
            // проверить указание параметров
            if (encoded is ASN1.Null) throw new NotSupportedException(); 
        
            // при указании идентификатора
            if (encoded is ASN1.ObjectIdentifier)
            {
                // раскодировать идентификатор параметров
               string oid = ((ASN1.ObjectIdentifier)encoded).Value; 
            
                // получить набор параметров
                ASN1.ANSI.X962.SpecifiedECDomain parameters = 
                    ASN1.ANSI.X962.SpecifiedECDomain.Parameters(oid); 
            
                // раскодировать набор параметров
                return DecodeParameters(oid, parameters); 
            }
            else { 
                // получить набор параметров
                ASN1.ANSI.X962.SpecifiedECDomain parameters = 
                    (ASN1.ANSI.X962.SpecifiedECDomain)encoded; 
        
                // раскодировать набор параметров
                return DecodeParameters(null, parameters); 
            }
        }
        public IParameters DecodeParameters(String oid, ASN1.ANSI.X962.SpecifiedECDomain parameters)
        {
            // извлечь тип поля
            ASN1.ObjectIdentifier fieldType = parameters.FieldID.FieldType; 
        
            // проверить тип поля
            if (fieldType.Value != ASN1.ANSI.OID.x962_c2_field) throw new InvalidDataException(); 
        
            // раскодировать конечное поле
            ASN1.ANSI.X962.CharacteristicTwo characteristics = new ASN1.ANSI.X962.CharacteristicTwo(
                parameters.FieldID.Parameters
            ); 
            // определить число битов
            int m = characteristics.M.Value.IntValue; EC.FieldF2m field;
        
            // определить тип поля
            string basisOID = characteristics.Basis.Value; 

            // в зависимости от типа базиса
            if (basisOID == ASN1.ANSI.OID.x962_c2_basis_pp)
            {
                // раскодировать параметры поля
                ASN1.ANSI.X962.Pentanomial pentanomial = new ASN1.ANSI.X962.Pentanomial(
                    characteristics.Parameters
                ); 
                // создать образующий многочлен
                Math.PolynomBuilder builder = new Math.PolynomBuilder(m + 1); 
            
                // установить биты образующего многочлена
                builder[m] = 1; builder[0] = 1;
            
                // установить биты образующего многочлена
                builder[pentanomial.K1.Value.IntValue] = 1;
                builder[pentanomial.K2.Value.IntValue] = 1;
                builder[pentanomial.K3.Value.IntValue] = 1;
            
                // создать конечное поле
                field = new EC.FieldF2m(new Math.F2m.PolyField(builder.ToPolynom())); 
            }
            // в зависимости от типа базиса
            else if (basisOID == ASN1.ANSI.OID.x962_c2_basis_tp)
            {
                // раскодировать параметры поля
                ASN1.Integer k = new ASN1.Integer(characteristics.Parameters); 

                // создать образующий многочлен
                Math.PolynomBuilder builder = new Math.PolynomBuilder(m + 1); 
            
                // установить биты образующего многочлена
                builder[m] = 1; builder[0] = 1; builder[k.Value.IntValue] = 1;
            
                // создать конечное поле
                field = new EC.FieldF2m(new Math.F2m.PolyField(builder.ToPolynom())); 
            }
            // в зависимости от типа базиса
            else if (basisOID == ASN1.ANSI.OID.x962_c2_basis_gn)
            {
                // создать конечное поле
                field = new EC.FieldF2m(new Math.F2m.NormField(m)); 
            }
            // при ошибке выбросить исключение
            else throw new InvalidDataException(); 
            
            // извлечь параметры эллиптической кривой
            ASN1.ANSI.X962.Curve curveParameters = parameters.Curve; Math.BigInteger n = parameters.Order.Value; 
        
            // раскодировать коэффициенты a и b
            Math.BigInteger a = Math.Convert.ToBigInteger(curveParameters.A.Value, Endian); 
            Math.BigInteger b = Math.Convert.ToBigInteger(curveParameters.B.Value, Endian); 
        
            // раскодировать параметры генерации
            byte[] seed = (curveParameters.Seed != null) ? curveParameters.Seed.Value : null;
            try { 
                // создать эллиптическую кривую
                EC.CurveF2m curve = new EC.CurveF2m(field, a, b, seed); 
        
                // раскодировать базовую точку
                EC.Point g = curve.Decode(parameters.Generator.Value); 
        
                // извлечь сомножитель
                Math.BigInteger cofactor = parameters.Cofactor.Value; if (oid == null) 
                {
                    // вернуть извлеченные параметры
                    return new Parameters(curve, g, n, cofactor, parameters.Hash); 
                }
                // вернуть именованный набор параметров
                else return new NamedParameters(oid, curve, g, n, cofactor, parameters.Hash); 
            }
            // при ошибке изменить тип исключения
            catch (ArgumentException e) { throw new InvalidDataException(e.Message, e); }
        }
    }
}
