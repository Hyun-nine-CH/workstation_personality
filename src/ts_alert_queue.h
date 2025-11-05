#include "linkedList.h"

typedef int AlertContent;

typedef struct alertNode{
    Node baseNode;
    AlertContent content;
} AlertNode;

typedef struct alertQueue{
    LinkedList baseList;
} AlertQueue;

extern void clear_alert(AlertContent* alertPtr);
extern void print_alert(const AlertContent* alertPtr);

extern void initialize_alertQueue(AlertQueue* list);
extern void clear_alertQueue(AlertQueue* queue);
extern int getSize_alertQueue(AlertQueue* queue);
extern int isEmpty_alertQueue(AlertQueue* queue);
extern void pop_alertQueue(AlertQueue* queue);
extern void push_alertQueue(AlertQueue* queue, AlertContent content);
extern AlertContent* peek_alertQueue(AlertQueue* queue);
extern AlertContent* peek_front_alertQueue(AlertQueue* queue);

extern void printList_alertQueue(AlertQueue* list);