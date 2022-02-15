using System;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Категория файла
    ///////////////////////////////////////////////////////////////////////////////
    public static class FileCategory 
    {
        // категория файла
        public const int Unknown   = 0x00; 
        public const int Working   = 0x01; 
        public const int Internal  = 0x02; 
        public const int Dedicated = 0x08; 
        public const int Shareable = 0x10; 
    }
}
