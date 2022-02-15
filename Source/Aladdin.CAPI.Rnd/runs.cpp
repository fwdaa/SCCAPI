#include "stdafx.h"
#include "stsnist.h"
#include "cprob.h"  

////////////////////////////////////////////////////////////////////////////////////
// 2.3 Runs Test
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
////////////////////////////////////////////////////////////////////////////////////
bool RunsTest(const BitSequence* epsilon, size_t n)
{
	// инициализировать переменные
	size_t S = 0; size_t V = 1; 

	// подсчитать число единиц в последовательности
	for (size_t k = 0; k < n; k++) if (epsilon[k]) S++;

	// выполнить 2.3.4.1 и вычислить pi * (1-pi)
	double pi = (double)S / n; double p = pi * (1- pi); 

	// выполнить 2.3.4.2
	if (fabs(pi - 0.5) > 2.0 / sqrt((double)n)) return false;

	// выполнить 2.3.4.3
	for (size_t k = 1; k < n; k++)
	{
		// подсчитать число соседних несовпадений
		if (epsilon[k] != epsilon[k-1]) V++;
	}
	// выполнить 2.3.4.4
	double p_value = erfc(fabs(V - 2.0 * n * p) / (2.0 * sqrt(2.0 * n) * p)); 

	// выполнить 2.3.5
	return (p_value >= 0.01); 
}
