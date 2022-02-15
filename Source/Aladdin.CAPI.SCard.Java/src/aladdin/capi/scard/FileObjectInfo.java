package aladdin.capi.scard;

///////////////////////////////////////////////////////////////////////////
// Описание объекта файловой системы
///////////////////////////////////////////////////////////////////////////
public class FileObjectInfo
{
    // предоставленные права на чтение
    private final int size; private final String[] readAccessUsers; 
    
    // предоставленные права на запись
    private final String[] writeAccessUsers;

    // конструктор
    public FileObjectInfo(int size, String[] readAccessUsers, String[] writeAccessUsers)
    {
        // сохранить переданные параметры
        this.size = size; this.readAccessUsers = readAccessUsers; 
        
        // сохранить переданные параметры
        this.writeAccessUsers = writeAccessUsers; 
    }
    // размер объекта
    public final int objectSize() { return size; } 

    // проверить наличие доступа на чтение
    public Boolean hasReadAccess(String user)
    {
        // проверить наличие пользователей
        if (readAccessUsers == null) return null; 

        // для всех допустимых пользователей
        for (String userName : readAccessUsers)
        {
            // проверить совпадение пользователя
            if (userName.equalsIgnoreCase(user)) return true; 
        }
        return false; 
    }
    // проверить наличие доступа на запись
    public final Boolean hasWriteAccess(String user)
    {
        // проверить наличие пользователей
        if (writeAccessUsers == null) return null;

        // для всех допустимых пользователей
        for (String userName : writeAccessUsers)
        {
            // проверить совпадение пользователя
            if (userName.equalsIgnoreCase(user)) return true; 
        }
        return false;
    }
}
