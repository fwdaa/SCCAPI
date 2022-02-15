using System; 

namespace Aladdin.CAPI.SCard
{
    ///////////////////////////////////////////////////////////////////////////
    // Описание объекта файловой системы
    ///////////////////////////////////////////////////////////////////////////
    public struct FileObjectInfo
    {
        // предоставленные права на чтение и запись
        private int size; private string[] readAccessUsers; private string[] writeAccessUsers;

        // конструктор
        public FileObjectInfo(int size, string[] readAccessUsers, string[] writeAccessUsers)
        {
            // сохранить переданные параметры
            this.size = size; this.readAccessUsers = readAccessUsers; this.writeAccessUsers = writeAccessUsers; 
        }
        // размер объекта
        public int ObjectSize { get { return size; }} 

        // проверить наличие доступа на чтение
        public bool? HasReadAccess(string user)
        {
            // проверить наличие пользователей
            if (readAccessUsers == null) return null; 

            // для всех допустимых пользователей
            foreach (string userName in readAccessUsers)
            {
                // проверить совпадение пользователя
                if (String.Compare(userName, user, true) == 0) return true; 
            }
            return false; 
        }
        // проверить наличие доступа на запись
        public bool? HasWriteAccess(string user)
        {
            // проверить наличие пользователей
            if (writeAccessUsers == null) return null;

            // для всех допустимых пользователей
            foreach (string userName in writeAccessUsers)
            {
                // проверить совпадение пользователя
                if (String.Compare(userName, user, true) == 0) return true;
            }
            return false;
        }
    }
}
