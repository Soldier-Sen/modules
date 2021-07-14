#include <stdio.h>


#define ARRAY_NUM(a) (sizeof(a) / sizeof(a[0]))

/*
冒泡排序
*/

int a[] = {6, 1, 2, 5, 9, 3, 4, 7, 10, 8};
int n = ARRAY_NUM(a);

void print_array(int *a, int num)
{
	int i = 0;
	for(i = 0; i < num; i++)
		printf("%d ", a[i]);
	printf("\n");
}

int quick_sort()
{

	int i, j;
	int tmp = 0, first = a[0];
	for(i = 0; i < n; i++)
	{

	}

	print_array(a, n);
}

int quickSortTest(void)
{
	quick_sort();
	return 0;
}
