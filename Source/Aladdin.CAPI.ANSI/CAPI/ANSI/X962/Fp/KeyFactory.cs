using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.X962.Fp
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
            EC.CurveFp ec = (EC.CurveFp)ecParameters.Curve; int cb = (ec.Field.FieldSize + 7) / 8;

            // указать идентификатор типа поля
            ASN1.ObjectIdentifier fieldType = new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_prime_field); 
        
            // закодировать параметры поля
            ASN1.ANSI.X962.FieldID fieldID = new ASN1.ANSI.X962.FieldID(
                fieldType, new ASN1.Integer(ec.Field.P)
            ); 
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
            ASN1.Integer encodedN = new ASN1.Integer(ecParameters.Order   ); 
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
        public IParameters DecodeParameters(string oid, ASN1.ANSI.X962.SpecifiedECDomain parameters)
        {
            // извлечь тип поля
            ASN1.ObjectIdentifier fieldType = parameters.FieldID.FieldType; 
        
            // проверить тип поля
            if (fieldType.Value != ASN1.ANSI.OID.x962_prime_field) throw new InvalidDataException(); 
        
            // раскодировать модуль поля
            ASN1.Integer modulus = new ASN1.Integer(parameters.FieldID.Parameters); 
        
            // извлечь параметры эллиптической кривой
            ASN1.ANSI.X962.Curve curveParameters = parameters.Curve; Math.BigInteger n = parameters.Order.Value;
        
            // раскодировать коэффициенты a и b
            Math.BigInteger a = Math.Convert.ToBigInteger(curveParameters.A.Value, Endian); 
            Math.BigInteger b = Math.Convert.ToBigInteger(curveParameters.B.Value, Endian); 
        
            // раскодировать параметр seed
            byte[] seed = (curveParameters.Seed != null) ? curveParameters.Seed.Value : null;
            try {  
                // создать эллиптическую кривую
                EC.CurveFp curve = new EC.CurveFp(modulus.Value, a, b, seed); 
        
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