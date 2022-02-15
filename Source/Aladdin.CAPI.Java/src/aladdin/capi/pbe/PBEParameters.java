package aladdin.capi.pbe;

///////////////////////////////////////////////////////////////////////////
// Параметры шифрования по паролю
///////////////////////////////////////////////////////////////////////////
public class PBEParameters
{
    // размер salt-значения и число итераций
    private final int pbmSaltLength; private final int pbmIterations; 
    private final int pbeSaltLength; private final int pbeIterations; 

    // конструктор
    public PBEParameters(int pbmSaltLength, int pbmIterations, int pbeSaltLength, int pbeIterations)
    {
        // сохранить переданные параметры
        this.pbmSaltLength = pbmSaltLength; this.pbmIterations = pbmIterations; 
        this.pbeSaltLength = pbeSaltLength; this.pbeIterations = pbeIterations; 
    }
    // размер salt-значения и число итераций
    public int pbmSaltLength() { return pbmSaltLength; }
    public int pbmIterations() { return pbmIterations; }
    public int pbeSaltLength() { return pbeSaltLength; }
    public int pbeIterations() { return pbeIterations; }
}
