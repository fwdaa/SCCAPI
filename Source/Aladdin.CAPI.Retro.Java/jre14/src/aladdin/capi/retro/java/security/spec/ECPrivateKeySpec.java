package aladdin.capi.retro.java.security.spec;
import java.security.spec.*; 
import java.math.*;

///////////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма на эллиптических кривых
///////////////////////////////////////////////////////////////////////////////
public class ECPrivateKeySpec implements KeySpec 
{
    // параметры и значение личного ключа
    private final ECParameterSpec params; private final BigInteger s; 
    
    // конструктор
    public ECPrivateKeySpec(BigInteger s, ECParameterSpec params) 
    {
        // проверить наличие параметров
        if (s      == null) throw new NullPointerException("s is null"    );
        if (params == null) throw new NullPointerException("params is null");
        
        // сохранить переданные параметры
        this.params = params; this.s = s;
    }
    // параметры ключа 
    public ECParameterSpec getParams() { return params; }
    // значение личного ключа 
    public BigInteger getS() { return s; } 
}
