package edu.emory.mathcs.backport.java.util.concurrent.helpers;
import edu.emory.mathcs.backport.java.util.Arrays;
import edu.emory.mathcs.backport.java.util.concurrent.*;
import edu.emory.mathcs.backport.java.util.concurrent.locks.*;
import java.lang.reflect.*;
import java.security.*;
import java.util.*;

public final class Utils 
{
    ///////////////////////////////////////////////////////////////////////////
    // Преобразование коллекции в массив
    ///////////////////////////////////////////////////////////////////////////
    public static Object[] collectionToArray(Collection c, Object[] a) 
    {
        // определить класс массива и размер коллекции
        Object[] arr = a; Class aType = a.getClass(); int len = c.size(); int idx = 0;
        
        // при необходимости выделить массив большего размера
        if (a.length < len) arr = (Object[])Array.newInstance(aType.getComponentType(), len);

        // для всех элементов коллекции
        for (Iterator itr = c.iterator(); itr.hasNext(); ) 
        {
            // для заполненного массива вычислить новый размер 
            if (idx >= len) { int newcap = (arr.length / 2 + 1) * 3;
             
                // при переполнении
                if (newcap < arr.length) 
                {
                    // проверить возможность увеличения
                    if (arr.length < Integer.MAX_VALUE) newcap = Integer.MAX_VALUE;
                
                    // при невозможности выбросить исключение
                    else throw new OutOfMemoryError("required array size too large");
                }
                // выделить новый массив и скопировать в него элементы
                arr = Arrays.copyOf(arr, newcap, aType); len = newcap;
            }
            // сохранить элемент в массив
            if (itr.hasNext()) arr[idx] = itr.next(); else break; 
        }
        // заполнить нулями оставшиеся элементы массива
        if (arr == a) { for (; idx < len; idx++) a[idx] = null; return a; }
        
        // выделить новый массив и скопировать в него элементы
        return (idx < len) ? Arrays.copyOf(arr, idx, aType) : arr;
    }
    public static Object[] collectionToArray(Collection c) 
    {
        // выделить массив требуемого размера
        int len = c.size(); Object[] arr = new Object[len]; int idx = 0;
        
        // для всех элементов коллекции
        for (Iterator itr = c.iterator(); itr.hasNext(); ) 
        {
            // для заполненного массива вычислить новый размер 
            if (idx >= len) { int newcap = (arr.length / 2 + 1) * 3;
            
                // при переполнении
                if (newcap < arr.length) 
                {
                    // проверить возможность увеличения
                    if (arr.length < Integer.MAX_VALUE) newcap = Integer.MAX_VALUE;
                
                    // при невозможности выбросить исключение
                    else throw new OutOfMemoryError("required array size too large");
                }
                // выделить новый массив и скопировать в него элементы
                arr = Arrays.copyOf(arr, newcap, Object[].class); len = newcap;
            }
            // сохранить элемент в массив
            if (itr.hasNext()) arr[idx] = itr.next(); else break; 
        }
        // выделить новый массив и скопировать в него элементы
        return (idx < len) ? Arrays.copyOf(arr, idx, Object[].class) : arr;
    }
    ///////////////////////////////////////////////////////////////////////////
    // Функция, выполняемая в привилегированном режиме
    ///////////////////////////////////////////////////////////////////////////
    private static final class NanoTimeSelection implements PrivilegedAction
    {
        public Object run() 
        {
            // указать имя свойства для класса таймера
            String property = "edu.emory.mathcs.backport.java.util.concurrent.NanoTimerProvider"; 
            
            // получить имя класса таймера
            return System.getProperty(property); 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Реализация таймеров
    ///////////////////////////////////////////////////////////////////////////
    static final class MillisProvider implements NanoTimer 
    {
        // получить значение системного таймера
        public long nanoTime() { return System.currentTimeMillis() * 1000000L; }
    }
    static final class SunPerfProvider implements NanoTimer 
    {
        // получить значение системного таймера (таймер Sun не используется)
        public long nanoTime() { return System.currentTimeMillis() * 1000000L; }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Инициализация таймера
    ///////////////////////////////////////////////////////////////////////////
    private static final NanoTimer nanoTimer;
    static {
        NanoTimer timer = null;
        try {
            // получить имя класса таймера
            String e = (String)AccessController.doPrivileged(new NanoTimeSelection());
            
            // создать класс таймера
            if(e != null) timer = (NanoTimer)Class.forName(e).newInstance(); 
        } 
        catch (Throwable e) 
        {
            // создать высокопроизводительный таймер
            try { timer = new SunPerfProvider(); } catch (Throwable ex) {} 
        }
        // при наличии ошибок использовать системный таймер
        nanoTimer = (timer != null) ? timer : new MillisProvider();
    }
    ///////////////////////////////////////////////////////////////////////////
    // Функции таймера
    ///////////////////////////////////////////////////////////////////////////
    public static long nanoTime() { return nanoTimer.nanoTime(); } 

    // ожидать событие до истечения таймера
    public static long awaitNanos(Condition cond, long nanosTimeout) throws InterruptedException 
    {
        // проверить указание тайм-аута
        if (nanosTimeout <= 0L) return nanosTimeout; long now = nanoTime();
        
        // ожидать событие до истечения таймера
        cond.await(nanosTimeout, TimeUnit.NANOSECONDS);
        
        // вернуть оставшееся время 
        return nanosTimeout - (nanoTime() - now);
    }
}
