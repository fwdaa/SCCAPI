package aladdin.iso7816;

///////////////////////////////////////////////////////////////////////////////
// Категория файла
///////////////////////////////////////////////////////////////////////////////
public abstract class FileCategory 
{
    // категория файла
    public static final int UNKNOWN   = 0x00; 
    public static final int WORKING   = 0x01; 
    public static final int INTERNAL  = 0x02; 
    public static final int DEDICATED = 0x08; 
    public static final int SHAREABLE = 0x10; 
}
