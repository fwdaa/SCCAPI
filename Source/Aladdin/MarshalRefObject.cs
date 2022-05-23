using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Aladdin
{
    ///////////////////////////////////////////////////////////////////////////
    // Объект со счетчиком ссылок
    ///////////////////////////////////////////////////////////////////////////
    // Вызов GC.SuppressFinalize нельзя производить в методе Dispose(),
    // поскольку в Managed C++ вызов деструктора приводит к явному вызову
    // Dispose(true), минуя Dispose(). В результате при выполнении сборки 
    // мусора будет выполнен метод Dispose(true), в котором счетчик ссылок 
    // будет равен 0. 
    ///////////////////////////////////////////////////////////////////////////
    [ComVisible(true)]
    public class MarshalRefObject : MarshalByRefObject, IRefObject
    {
#if DEBUG
        // счетчик ссылок и стек вызова
        private int refs; private string stackTrace; 

        // конструктор
        public MarshalRefObject() { this.refs = 1; stackTrace = Environment.StackTrace; }

        // деструктор
        ~MarshalRefObject() { try { Dispose(false); } catch {} }
#else 
        // конструктор
        public MarshalRefObject() { this.refs = 1; } private int refs; 
#endif 
        // увеличить счетчик ссылок
        public void AddRef() { refs++; } 

        // уменьшить счетчик ссылок
        public void Release() { Dispose(); }

        // уменьшить счетчик ссылок
        public void Dispose() { if (refs > 1) --refs; else Dispose(true); } 
        
        // освободить выделенные ресурсы
        protected virtual void Dispose(bool disposing) 
        {
            // освободить выделенные ресурсы
            if (disposing) { try { OnDispose(); } finally { --refs; GC.SuppressFinalize(this); }} 
#if DEBUG
            // проверить наличие трассировки
            if (!String.IsNullOrEmpty(stackTrace) && (!disposing || refs != 0))
            { 
                // сформировать строку описания
                string message = String.Format("{0}:{1}\n{2}", refs, GetType(), stackTrace); 

                // вывести строку
                Console.WriteLine(message); Debug.Print(message); 
            }
#endif 
        }
        // освободить выделенные ресурсы
        protected virtual void OnDispose() {}
    }
}
