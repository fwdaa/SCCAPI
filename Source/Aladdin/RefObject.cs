using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Aladdin
{
    ///////////////////////////////////////////////////////////////////////////
    // Объект со счетчиком ссылок.
    ///////////////////////////////////////////////////////////////////////////
    // Вызов GC.SuppressFinalize нельзя производить в методе Dispose(),
    // поскольку в Managed C++ вызов деструктора приводит к явному вызову
    // Dispose(true), минуя Dispose(). В результате при выполнении сборки 
    // мусора будет выполнен метод Dispose(true), в котором счетчик ссылок 
    // будет равен 0. 
    ///////////////////////////////////////////////////////////////////////////
    [ComVisible(true)]
    public class RefObject : IRefObject
    {
        // увеличить счетчик ссылок
        public static T AddRef<T>(T obj) where T : IRefObject
        { 
            // увеличить счетчик ссылок
            if (obj != null) obj.AddRef(); return obj; 
        }
        // уменьшить счетчик ссылок
        public static void Release(IRefObject obj) { if (obj != null) obj.Release(); }
#if DEBUG            
        // счетчик ссылок и стек вызова
        private int refs; private string stackTrace; 

        // конструктор
        public RefObject() { this.refs = 1; stackTrace = Environment.StackTrace; }

        // деструктор
        ~RefObject() { try { Dispose(false); } catch {} }
#else 
        // конструктор
        public RefObject() { this.refs = 1; } private int refs; 
#endif 
        // увеличить/уменьшить счетчик ссылок
        public void AddRef() { refs++; } public void Release() { Dispose(); }

        // уменьшить счетчик ссылок
        public void Dispose() { if (refs > 1) --refs; else Dispose(true); } 
            
        // освободить выделенные ресурсы
        protected virtual void Dispose(bool disposing) 
        {
            // освободить выделенные ресурсы
            if (disposing) { try { OnDispose(); } finally { --refs; GC.SuppressFinalize(this); }} 
#if DEBUG        
            // проверить наличие трассировки
            else if (!String.IsNullOrEmpty(stackTrace))
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
