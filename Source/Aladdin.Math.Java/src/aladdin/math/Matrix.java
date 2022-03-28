package aladdin.math;
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
// Матрица (unused   , ..., unused       )
//         (a_0_0    , ..., a_0_{m-1}    )
//         (  ...    , ...,   ...        )
//         (a_{m-1}_0, ..., a_{m-1}_{m-1})
////////////////////////////////////////////////////////////////////////////////
public final class Matrix implements Serializable
{
    private static final long serialVersionUID = 5561089138698459516L;
    
    // столбцы матрицы и число строк
    private final Vector[] columns; private final int rows; 
    
    // конструктор 
    protected Matrix(Vector[] columns, int rows) 
    {     
        // сохранить переданные параметры
        this.columns = columns; this.rows = rows; 
    } 
    // столбцы матрицы
    public final Vector[] columns() { return columns; }

    // число строк матрицы
    public final int rows() { return rows; }
    
    // получить значение бита
    public final int get(int i, int j) { return columns[j].get(i); }
}
