using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Данные CMS
    ///////////////////////////////////////////////////////////////////////////////
    public class CMSData 
    {
        // конструктор
        public CMSData(String type, byte[] content) { Type = type; Content = content; }
    
        // тип данных и их содержимое
        public readonly String Type; public readonly byte[] Content; 
    }
}
