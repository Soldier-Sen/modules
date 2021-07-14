#include <stdio.h>

/*
冒泡排序
*/
int bubble()
{
	int a[] = {5, 3, 7, 8, 9, 10};
	int n = sizeof(a) / sizeof(a[0]);
	int i = 0, j = 0;
	int tmp = 0;
	for(i = 0; i < n - 1; i++)
	{
		for(j = 0; j < n - i - 1; j++)
		{
			//if(a[j] < a[j+1]) // 从大到小排序
			if(a[j] > a[j+1])	// 从小到大排序
			{
				tmp = a[j+1]; a[j+1] = a[j]; a[j] = tmp;
			}
		}
	}
	for(i = 0; i < n; i++)
		printf("%d ", a[i]);
	printf("\n");
}

int bubbleSortTest(void)
{
	bubble();
	return 0;
}
