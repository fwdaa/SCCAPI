#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int main_enrol(void);
extern int main_verify2(void);

/****************************************************************************
*
* Main - Simple test program to launch the enroll and verify examples.
*
****************************************************************************/
int main(void)
{
    int  ret = 0;
    int  selection = -1;
    char stdin_string[20];

    while (1) 
    {
        printf("\n\n\n**************Precise Biometrics C Examples**************\n");
        printf("1. MoC enrollment.\n");
        printf("2. MoC verification.\n");
        printf("0. Exit.\n");
        printf("*********************************************************\n");
        printf("\nChoose test to run by entering the test number: ");
        fgets(stdin_string, 20, stdin);
        selection = stdin_string[0] - 48;
        
        if (selection == 0) 
        {
            break;
        }

        switch(selection) 
        {
            case 1:
                main_enrol();
                break;
            case 2:
                main_verify2();
                break;
            default:
                break;
        }
        selection = -1;
    }

    return ret;
}