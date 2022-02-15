namespace Aladdin.CAPI.Bio.BSAPI
{
    ///////////////////////////////////////////////////////////////////////
    // Описание этапа 
    ///////////////////////////////////////////////////////////////////////
    public class Process
    {
        // конструктор
        public Process(Process parent, ProcessID id) { Parent = parent; ID = id; }

        // родительский этап и тип текущего этапа
        public readonly Process Parent; public readonly ProcessID ID;
    }
}
