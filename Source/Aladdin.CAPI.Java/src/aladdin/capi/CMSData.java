package aladdin.capi;

///////////////////////////////////////////////////////////////////////////////
// Данные CMS
///////////////////////////////////////////////////////////////////////////////
public class CMSData 
{
    // конструктор
    public CMSData(String type, byte[] content) 
    { 
        // сохранить переданные параметры
        this.type = type; this.content = content; 
    }
    // тип данных и их содержимое
    public final String type; public final byte[] content; 
}
