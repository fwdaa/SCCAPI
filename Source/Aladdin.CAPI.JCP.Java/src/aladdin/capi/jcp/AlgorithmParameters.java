package aladdin.capi.jcp;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма 
///////////////////////////////////////////////////////////////////////////////
public final class AlgorithmParameters extends java.security.AlgorithmParameters
{
    // реализация параметров алгоритма
    private final AlgorithmParametersSpi spi; 
    
    // конструктор
    public AlgorithmParameters(Provider provider, AlgorithmParametersSpi spi)
    {
        // сохранить переданные параметры
        super(spi, provider, spi.getAlgorithm()); this.spi = spi; 
    }
    // реализация параметров алгоритма
    public final AlgorithmParametersSpi spi() { return spi; } 
}
