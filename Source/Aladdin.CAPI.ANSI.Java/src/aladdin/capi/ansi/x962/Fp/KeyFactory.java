package aladdin.capi.ansi.x962.Fp;
import aladdin.capi.ec.*;
import aladdin.capi.ansi.x962.*;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.ansi.*;
import aladdin.asn1.ansi.x962.*;
import aladdin.math.*;
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
        CurveFp ec = (CurveFp)ecParameters.getCurve(); 
        
        // получить используемое поле
        ECFieldFp field = ec.getField(); int cb = (field.getFieldSize() + 7) / 8; 
        
        // указать идентификатор типа поля
        ObjectIdentifier fieldType = new ObjectIdentifier(OID.X962_PRIME_FIELD); 
        
        // закодировать параметры поля
        FieldID fieldID = new FieldID(fieldType, new Integer(field.getP())); 
        
        // закодировать параметры a и b кривой
        OctetString encodedA = new OctetString(Convert.fromBigInteger(ec.getA(), ENDIAN, cb));
        OctetString encodedB = new OctetString(Convert.fromBigInteger(ec.getB(), ENDIAN, cb));
            
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
        if (!fieldType.value().equals(OID.X962_PRIME_FIELD)) throw new IOException(); 
        
        // раскодировать модуль поля
        Integer modulus = new Integer(parameters.fieldID().parameters()); 
        
        // извлечь параметры эллиптической кривой
        aladdin.asn1.ansi.x962.Curve curveParameters = parameters.curve(); 
        
        // раскодировать коэффициенты a и b
        BigInteger a = Convert.toBigInteger(curveParameters.a().value(), ENDIAN); 
        BigInteger b = Convert.toBigInteger(curveParameters.b().value(), ENDIAN); 
        
        // раскодировать параметр seed
        byte[] seed = (curveParameters.seed() != null) ? curveParameters.seed().value() : null;
        
        // создать эллиптическую кривую
        CurveFp curve = new CurveFp(modulus.value(), a, b, seed); 
        
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
