using System;

namespace Aladdin
{
///////////////////////////////////////////////////////////////////////////////
// Автоматическое освобождение ресурсов
///////////////////////////////////////////////////////////////////////////////
public sealed class Using<T> : Disposable where T : IDisposable
{
	// конструктор
	public Using(T obj) { this.obj = obj; }
	// конструктор
    public Using() : this(default(T)) {}

	// деструктор
	protected override void OnDispose() 
    { 
	    // освободить выделенные ресурсы
	    if (obj != null) obj.Dispose(); obj = default(T); base.OnDispose(); 
    }
	// внутренний объект
	public T Get() { return obj; } private T obj;

    // сохранить внутренний объект
    public void Attach(T obj) { this.obj = obj; }
    public T    Detach() 
    { 
        // открепить внутренний объект
        T obj = this.obj; this.obj = default(T); return obj; 
    }
};
}
