namespace Aladdin.CAPI.SCard
{
    ///////////////////////////////////////////////////////////////////////////
    // Файл апплета
    ///////////////////////////////////////////////////////////////////////////
    public interface IAppletFile : IAppletFileObject
    {
        // прочитать данные выбранного файла
        void Read(byte[] buffer, int offset);  

        // записать данные в выбранный файл
        void Write(byte[] buffer, int offset);
    }
}
