package aladdin.capi.ansi.x962.F2m;
import aladdin.capi.ec.*;
import aladdin.capi.ansi.x962.*;
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.ansi.*;
import aladdin.asn1.ansi.x962.*;
import java.security.spec.*; 
import java.math.*;
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
// Фабрика кодирования кючей
////////////////////////////////////////////////////////////////////////////////
public class KeyFactory extends aladdin.capi.ansi.x962.KeyFactory
{
    // указать способ кодирования
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // конструктор
    public KeyFactory(String keyOID) { super(keyOID); }
    
    @Override public IEncodable encodeParameters(
        aladdin.capi.IParameters parameters, Encoding encoding, boolean useOID) 
    {
        // при указании идентификатора 
        if (parameters instanceof NamedParameters && useOID)
        {
            // закодировать идентификатор параметров
            return new ObjectIdentifier(((NamedParameters)parameters).oid()); 
        }
        // преобразовать тип параметров
        aladdin.capi.ansi.x962.IParameters ecParameters = 
            (aladdin.capi.ansi.x962.IParameters)parameters; 
            
        // получить описание эллиптической кривой
        CurveF2m ec = (CurveF2m)ecParameters.getCurve(); 
        
        // получить используемое поле
        ECFieldF2m field = ec.getField(); int m = field.getM(); 
        
        // указать идентификатор типа поля
        ObjectIdentifier fieldType = new ObjectIdentifier(OID.X962_C2_FIELD); 
            
        // иниуиализировать переменные
        String oid = null; IEncodable fieldParameters = null; int cb = (m + 7) / 8;  
            
        // в зависимости от типа поля
        if (field.getReductionPolynomial() == null)
        {
            // указать отсутствие параметров
            oid = OID.X962_C2_BASIS_GN; fieldParameters = Null.INSTANCE;
        }
        else {
            // получить образующий многочлен
            BigInteger polynom = field.getReductionPolynomial(); 
                
            // создать список установленных степеней многочлена
            Integer[] k = new Integer[3]; int count = 0; 
                
            // для всех коэффициентов многочлена
            for (int i = 1; i < m; i++)
            {
                // проверить наличие степени
                if (!polynom.testBit(i)) continue; 
                    
                // проверить корректность степени
                if (count >= k.length) throw new IllegalArgumentException(); 
                    
                // сохранить индекс степени
                k[count] = new Integer(i); count++; 
            }
            // закодировать параметры
            if (count == 1) { oid = OID.X962_C2_BASIS_TP; fieldParameters = k[0]; } 
                
            // для пентаномов
            else if (count == 3) { oid = OID.X962_C2_BASIS_PP;
               
                // закодировать параметры
                fieldParameters = new Pentanomial(k[0], k[1], k[2]); 
            }
        }
        // при ошибке выбросить исключение
        if (oid == null) throw new IllegalArgumentException(); 
            
        // закодировать характеристики поля
        CharacteristicTwo characteristics = new CharacteristicTwo(
            new Integer(m), new ObjectIdentifier(oid), fieldParameters
        ); 
        // закодировать параметры поля
        FieldID fieldID = new FieldID(fieldType, characteristics); 
            
        // закодировать параметры a и b кривой
        OctetString encodedA = new OctetString(Convert.fromBigInteger(ec.getA(), ENDIAN, cb));
        OctetString encodedB = new OctetString(Convert.fromBigInteger(ec.getA(), ENDIAN, cb));
            
        // при наличии параметров генерации
        BitString encodedSeed = null; if (ec.getSeed() != null) 
        {
            // закодировать параметры генерации
            encodedSeed = new BitString(ec.getSeed());
        } 
        // закодировать базовую точку эллиптической кривой
        OctetString encodedG = new OctetString(ec.encode(ecParameters.getGenerator(), encoding));
            
        // закодировать порядок базовой точки
        Integer encodedN = new Integer(ecParameters.getOrder   ()); 
        Integer encodedH = new Integer(ecParameters.getCofactor()); 
            
        // закодировать параметры эллиптической кривой
        aladdin.asn1.ansi.x962.Curve encodedEC = 
            new aladdin.asn1.ansi.x962.Curve(encodedA, encodedB, encodedSeed); 
            
        // закодировать параметры в целом
        return new SpecifiedECDomain(new Integer(1), fieldID, 
            encodedEC, encodedG, encodedN, encodedH, ecParameters.getHash()
        ); 
    }
    @Override public Parameters decodeParameters(IEncodable encoded) throws IOException 
    {
        // раскодировать параметры
        encoded = new ECDomainParameters().decode(encoded); 
        
        // проверить указание параметров
        if (encoded instanceof Null) throw new UnsupportedOperationException(); 
        
        // при указании идентификатора
        if (encoded instanceof ObjectIdentifier)
        {
            // раскодировать идентификатор параметров
           String oid = ((ObjectIdentifier)encoded).value(); 
            
            // получить набор параметров
            SpecifiedECDomain parameters = SpecifiedECDomain.parameters(oid); 
            
            // раскодировать набор параметров
            return decodeParameters(oid, parameters); 
        }
        else { 
            // получить набор параметров
            SpecifiedECDomain parameters = (SpecifiedECDomain)encoded; 
        
            // раскодировать набор параметров
            return decodeParameters(null, parameters); 
        }
    }
    public Parameters decodeParameters(String oid, SpecifiedECDomain parameters) throws IOException 
    {
        // извлечь тип поля
        ObjectIdentifier fieldType = parameters.fieldID().fieldType(); 
        
        // проверить тип поля
        if (!fieldType.value().equals(OID.X962_C2_FIELD)) throw new IOException(); 
        
        // раскодировать конечное поле
        CharacteristicTwo characteristics = new CharacteristicTwo(parameters.fieldID().parameters()); 
        
        // определить число битов
        int m = characteristics.m().value().intValue(); FieldF2m field;
        
        // определить тип поля
        String basisOID = characteristics.basis().value(); 

        // в зависимости от типа базиса
        if (basisOID.equals(OID.X962_C2_BASIS_GN)) field = new FieldF2m(m);
        
        // в зависимости от типа базиса
        else if (basisOID.equals(OID.X962_C2_BASIS_PP))
        {
            // раскодировать параметры поля
            Pentanomial pentanomial = new Pentanomial(characteristics.parameters()); 
            
            // создать образующий многочлен
            PolynomBuilder builder = new PolynomBuilder(m + 1); 
            
            // установить биты образующего многочлена
            builder.set(m, 1); builder.set(0, 1);
            
            // установить биты образующего многочлена
            builder.set(pentanomial.k1().value().intValue(), 1);
            builder.set(pentanomial.k2().value().intValue(), 1);
            builder.set(pentanomial.k3().value().intValue(), 1);
            
            // создать конечное поле
            field = new FieldF2m(m, builder.toPolynom().toBigInteger()); 
        }
        // в зависимости от типа базиса
        else if (basisOID.equals(OID.X962_C2_BASIS_TP))
        {
            // раскодировать параметры поля
            Integer k = new Integer(characteristics.parameters()); 

            // создать образующий многочлен
            PolynomBuilder builder = new PolynomBuilder(m + 1); 
            
            // установить биты образующего многочлена
            builder.set(m, 1); builder.set(0, 1);
            
            // установить биты образующего многочлена
            builder.set(k.value().intValue(), 1);
            
            // создать конечное поле
            field = new FieldF2m(m, builder.toPolynom().toBigInteger()); 
        }
        // при ошибке выбросить исключение
        else throw new IOException(); 
            
        // извлечь параметры эллиптической кривой
        aladdin.asn1.ansi.x962.Curve curveParameters = parameters.curve(); 
        
        // раскодировать коэффициенты a и b
        BigInteger a = Convert.toBigInteger(curveParameters.a().value(), ENDIAN); 
        BigInteger b = Convert.toBigInteger(curveParameters.b().value(), ENDIAN); 
        
        // раскодировать параметры генерации
        byte[] seed = (curveParameters.seed() != null) ? curveParameters.seed().value() : null;
        
        // создать эллиптическую кривую
        CurveF2m curve = new CurveF2m(field, a, b, seed);         
        
        // раскодировать базовую точку
        ECPoint g = curve.decode(parameters.base().value()); 
        
        // извлечь порядок базовой точки
        BigInteger n = parameters.order().value(); 
        
        // извлечь сомножитель
        int cofactor = parameters.cofactor().value().intValue(); if (oid == null) 
        {
            // вернуть извлеченные параметры
            return new Parameters(curve, g, n, cofactor, parameters.hash()); 
        }
        // вернуть именованный набор параметров
        else return new NamedParameters(oid, curve, g, n, cofactor, parameters.hash()); 
    }
}
