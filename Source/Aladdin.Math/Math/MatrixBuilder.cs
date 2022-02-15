using System;

namespace Aladdin.Math
{
    ////////////////////////////////////////////////////////////////////////////
    // Создание матрицы
    ////////////////////////////////////////////////////////////////////////////
    public sealed class MatrixBuilder
    {
        // коэффициенты вектора и число строк
        private VectorBuilder[] columns; private int rows;

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
        public int this[int i, int j] 
        { 
            // получить значение бита
            get { return columns[j][i]; }

            // установить значение бита
            set { columns[j][i] = value; } 
        }
        // изменить значение бита
        public void Invert(int i, int j) { columns[j].Invert(i); }
    
        // завершить преобразование
        public Matrix ToMatrix() 
        { 
            // создать список столбцов
            Vector[] list = new Vector[columns.Length];  
        
            // заполнить список столбцов
            for (int i = 0; i < columns.Length; i++)
            {
                // заполнить список столбцов
                list[i] = columns[i].ToVector(); 
            }
            // вернуть созданную матрицу
            return new Matrix(list, rows); 
        }
    }
}
