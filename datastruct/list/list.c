#include <stdio.h>
#include <stdlib.h>

typedef int DataType;

typedef struct node{
	DataType data;
	struct node *prior, *next;
}Node;

Node *SingListCreate(DataType *a, int num)
{
	Node *first = (Node *)malloc(sizeof(Node));
	Node *p, *s;
	p = first;
	for(int i = 0; i < num; i++)
	{
		s = (Node *)malloc(sizeof(Node));
		s->data = a[i];
		p->next = s;
		p = p->next;
	}
	p->next = NULL;
	return first;
}

void SingListPrint(Node *first)
{
	Node *p = first->next;
	while(p)
	{
		printf("%d ", p->data);
		p = p->next;
	}
	printf("\n");
}


int SingListLength(Node *first)
{
	Node *p = first->next;
	int count = 0;
	while(p)
	{
		p = p->next;
		count++;
	}
	return count;
}

int SingListInsert(Node *first, DataType x, int i)
{
	Node *p = first->next;
	int count = 1;
	while(p && count < i - 1)
	{
		p = p->next;
		count++;
	}
	if(!p)
	{
		printf("not find i = %d index node\n", i);
		return -1;
	}
	else
	{
		Node *s = (Node *)malloc(sizeof(Node));
		s->data = x;
		s->next = p->next;
		p->next = s;
	}
	return 0;
}

int SingListDeleteByValue(Node *first, DataType x)
{
	Node *p = first->next;
	Node *pre = first;
	int index = 1;
	while(p)
	{
		if(p->data == x)
		{
			Node *x = p;
			pre->next = p->next;
			//p = p->next;
			free(x);
			break;
		}
		pre = p;
		p = p->next;
		index++;
	}
	return index;
}

int SingListDeleteByIndex(Node *first, int i)
{
	Node *p = first;
	int count = 1;
	if(i < 1) 
	{
		printf("i = %d < 1,rang is [1 - n]\n", i);
		return -1;
	}
	while(p && count < i)
	{
		p = p->next;
		count++;
	}
	
	if(p->next) {
		Node *x = p->next;
		p->next = x->next;
		free(x);
	}
}

// 选择排序
int SingListSelectSort(Node *first)
{
	Node *p = first->next;
	Node *q = NULL;
	DataType tmp;
	while(p)
	{
		q = p->next;
		while(q)
		{
			if(q->data > p->data) // 降序
			//if(q->data < p->data) // 增序
			{
				tmp = q->data;
				q->data = p->data;
				p->data = tmp;
			}
			q = q->next;
			//SingListPrint(first);
		}
		//printf("\n");
		p = p->next;
	}
}

// 冒泡排序
int SingListBubbleSort(Node *first)
{
	Node *p = first->next;
	Node *q = NULL;
	DataType tmp;
	while(p)
	{
		q = p;
		while(q->next)
		{
			//if(q->data < q->next->data)	// 增序
			if(q->data > q->next->data)  // 降序
			{
				tmp = q->data;
				q->data = q->next->data;
				q->next->data = tmp;
			}
			q = q->next;
		}
		tmp = q->data;
		q->data = p->data;
		p->data = tmp;
		p = p->next;
	}
}


int singListTest(void)
{
	DataType a[] = {3, 5, 2, 8, 6, 10};
	Node *Alist = SingListCreate(a, sizeof(a)/sizeof(a[0]));
	printf("Alist len = %d\n", SingListLength(Alist));
	SingListPrint(Alist);
	DataType x = 11;
	SingListInsert(Alist, x, 7);
	SingListPrint(Alist);
	printf("------------\n");
	//SingListSelectSort(Alist);
	//printf("选择排序: ");
	//SingListPrint(Alist);
	printf("冒泡排序: ");
	SingListBubbleSort(Alist);
	SingListPrint(Alist);
	printf("按索引删除: ");
	SingListDeleteByIndex(Alist, 8);
	SingListPrint(Alist);
	
	printf("按值删除: ");
	SingListDeleteByValue(Alist, 6);
	SingListPrint(Alist);
	return 0;
}


