package aladdin.math;

////////////////////////////////////////////////////////////////////////////
// Создание матрицы
////////////////////////////////////////////////////////////////////////////
public final class MatrixBuilder
{
    // коэффициенты вектора и число строк
    private final VectorBuilder[] columns; private final int rows;

    // конструктор
    public MatrixBuilder(int rows, int columns) 
    {
        // создать список столбцов
        this.columns = new VectorBuilder[columns]; this.rows = rows; 

        // для каждого столбца 
        for (int i = 0; i < columns; i++)
        {
            // выделить память для столбца 
            this.columns[i] = new VectorBuilder(rows); 
        }
    }
    // получить значение бита
    public final int get(int i, int j) { return columns[j].get(i); }
        
    // установить значение бита
    public final void set(int i, int j, int value)
    {
        // установить значение бита
        columns[j].set(i, value);
    }
    // изменить значение бита
    public final void invert(int i, int j) { columns[j].invert(i); }
        
    // завершить преобразование
    public final Matrix toMatrix() 
    { 
        // создать список столбцов
        Vector[] list = new Vector[columns.length];  
            
        // заполнить список столбцов
        for (int i = 0; i < columns.length; i++)
        {
            // заполнить список столбцов
            list[i] = columns[i].toVector(); 
        }
        // вернуть созданную матрицу
        return new Matrix(list, rows); 
    }
}
