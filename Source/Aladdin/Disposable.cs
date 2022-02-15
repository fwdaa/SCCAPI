using System;
using System.Diagnostics; 
using System.Runtime.InteropServices;

namespace Aladdin
{
    ///////////////////////////////////////////////////////////////////////////
    // Освобождаемый объект
    ///////////////////////////////////////////////////////////////////////////
    // Вызов GC.SuppressFinalize нельзя производить в методе Dispose(),
    // поскольку в Managed C++ вызов деструктора приводит к явному вызову
    // Dispose(true), минуя Dispose(). В результате при выполнении сборки 
    // мусора будет выполнен метод Dispose(true), в котором счетчик ссылок 
    // будет равен 0. 
    ///////////////////////////////////////////////////////////////////////////
    [ComVisible(true)]
    public class Disposable : IDisposable
    {
#if DEBUG            
        // конструктор
        public Disposable() { stackTrace = Environment.StackTrace; }

        // стек вызова
        private string stackTrace;
#endif
        // деструктор
        ~Disposable() { try { Dispose(false); } catch {} }

        // освободить выделенные ресурсы
        public void Close() { Dispose(); }

        // освободить выделенные ресурсы
        public void Dispose() { Dispose(true); }

        // освободить выделенные ресурсы
        protected virtual void Dispose(bool disposing)
        {
            // освободить выделенные ресурсы
            if (disposing) { try { OnDispose(); } finally { GC.SuppressFinalize(this); } } 
#if DEBUG            
            // проверить наличие трассировки
            else if (!String.IsNullOrEmpty(stackTrace))
            { 
                // сформировать строку описания
                string message = String.Format("{0}\n{1}", GetType(), stackTrace);

                // вывести строку
                Console.WriteLine(message); Debug.Print(message);
            }
#endif
        }
        // освободить выделенные ресурсы
        protected virtual void OnDispose() {}
    }
}
