package aladdin.capi.retro.java.security.spec;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма на эллиптических кривых
///////////////////////////////////////////////////////////////////////////////
public class ECPublicKeySpec implements KeySpec 
{
    // параметры и значение открытого ключа
    private final ECParameterSpec params; private final ECPoint w; 

    // конструктор
    public ECPublicKeySpec(ECPoint w, ECParameterSpec params) 
    {
        // проверить наличие параметров
        if (w      == null) throw new NullPointerException("w is null"     );
        if (params == null) throw new NullPointerException("params is null");
        
        // при указании бесконечной точки
        if (w == ECPoint.POINT_INFINITY) 
        {
            // выбросить исключение
            throw new IllegalArgumentException("w is ECPoint.POINT_INFINITY");
        }
        // сохранить переданные параметры
        this.params = params; this.w = w;
    }
    // параметры ключа 
    public ECParameterSpec getParams() { return params; }
    // значение открытого ключа 
    public ECPoint getW() { return w; }
}
