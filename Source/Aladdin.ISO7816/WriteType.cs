using System;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Cпособ записи в файл
    ///////////////////////////////////////////////////////////////////////////////
    public enum WriteType {
        Proprietary = 0, // Proprietary
        WriteErased = 1, // One-time write
        WriteOr     = 2, // Write OR
        WriteAnd    = 3  // Write AND
    }
}
