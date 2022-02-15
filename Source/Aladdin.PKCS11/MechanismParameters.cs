using System;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры механизма
    ///////////////////////////////////////////////////////////////////////////
    public interface MechanismParameters
    {
        // определить требуемый размер буфера
        int GetBufferSize(Module module); 

        // закодировать параметры
        object Encode(Module module, IntPtr ptr); 
    }
}
