package aladdin.capi.jcp;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма
///////////////////////////////////////////////////////////////////////////////
public final class AlgorithmParameters extends java.security.AlgorithmParameters
{
    // реализация класса параметров
    private final AlgorithmParametersSpi spi;
    
    // конструктор
    public AlgorithmParameters(Provider provider, AlgorithmParametersSpi spi)
    {
        // сохранить переданные параметры
        super(spi, provider, spi.getEncodable().algorithm().value()); this.spi = spi; 
    }
    // реализация класса параметров
    public final AlgorithmParametersSpi spi() { return spi; }
}
