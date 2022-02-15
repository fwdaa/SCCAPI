package aladdin.capi.stb.stb34101;
import aladdin.capi.*; 
import aladdin.capi.ec.*; 
import java.security.spec.*;
import java.math.*;

///////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров
///////////////////////////////////////////////////////////////////////////////
public class NamedParameters extends Parameters implements INamedParameters 
{
    // конструктор
    public NamedParameters(String oid, CurveFp ec, ECPoint g, BigInteger q)
    { 
        // сохранить переданные параметры
        super(ec, g, q); this.oid = oid; 
    }
    // идентификатор параметорв
    @Override public final String oid() { return oid; } private final String oid; 
}
