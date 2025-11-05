#include "ts_alert_queue.h"
#include <stdio.h>
#include <stdlib.h>

void clear_alert(AlertContent *alertPtr)
{
   
}

void print_alert(const AlertContent *alertPtr)
{
    printf("%d\n", *alertPtr);
}

void initialize_alertQueue(AlertQueue *list)
{
    initialize_linkedList((LinkedList*)list);
}

void clear_alertQueue(AlertQueue *queue)
{
    while(!isEmpty_alertQueue(queue)){
        AlertContent* peeked = peek_front_alertQueue(queue);
        clear_alert(peeked);
        AlertNode* toDelete = (AlertNode*)peek_back_linkedList((LinkedList*)queue);
        pop_alertQueue(queue);
    }
}

int getSize_alertQueue(AlertQueue *queue)
{
    return getSize_linkedList((LinkedList*)queue);
}

int isEmpty_alertQueue(AlertQueue *queue)
{
    return isEmpty_linkedList((LinkedList*)queue);
}

void pop_alertQueue(AlertQueue *queue)
{
    pop_back_linkedList((LinkedList*)queue);
}

void push_alertQueue(AlertQueue *queue, AlertContent content)
{
    AlertNode* newAlert = (AlertNode*)malloc(sizeof(AlertNode));

    newAlert->content = content;

    push_front_linkedList((LinkedList*)queue, (Node*)newAlert);
}

AlertContent *peek_alertQueue(AlertQueue *queue)
{
    return &((AlertNode*)peek_back_linkedList((LinkedList*)queue))->content;
}

AlertContent *peek_front_alertQueue(AlertQueue *queue)
{
    return &((AlertNode*)peek_front_linkedList((LinkedList*)queue))->content;
}

void printList_alertQueue(AlertQueue *list)
{
    AlertNode* present = NULL;
    present = (AlertNode*)peek_front_linkedList((LinkedList*)list);

    while(present != NULL){
        print_alert(&present->content);
        present = (AlertNode*)(present->baseNode.next);
    }
}