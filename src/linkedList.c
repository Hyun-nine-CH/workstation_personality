#include "linkedList.h"
#include <stdio.h>
#include <stdlib.h>

void initialize_linkedList(LinkedList *list)
{
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}

void clear_linkedList(LinkedList *list)
{
    while(!isEmpty_linkedList(list)){
        pop_back_linkedList(list);
    }
}

int getSize_linkedList(LinkedList *list)
{
    return list->size;
}

int isEmpty_linkedList(LinkedList * list)
{
    return list->size == 0;
}

void pop_back_linkedList(LinkedList *list)
{
    Node* toDelete = list->tail;

    if(list->tail){
        if(list->tail == list->head){
            list->head = NULL;
        }

        list->tail = list->tail->prev;
        
        free(toDelete);
        
        if(list->tail){
            list->tail->next = NULL;
        }
        list->size--;
    }
}

void pop_front_linkedList(LinkedList *list)
{
    Node* toDelete = list->head;
    
    if(list->head){
        if(list->tail == list->head){
            list->tail = NULL;
        }

        list->head = list->head->next;

        free(toDelete);
        if(list->head){
            list->head->prev = NULL;
        }
        list->size--;
    }
}

void push_back_linkedList(LinkedList *list,  Node* node)
{
    node->next = NULL;
    node->prev = NULL;
    // 노드가 비어있음
    if(isEmpty_linkedList(list)){
        list->head = node;
    }
    // 노드가 하나 이상 있음
    else {
        list->tail->next = node;
        node->prev = list->tail;
    }
    list->tail = node;
    list->size++;
}

void push_front_linkedList(LinkedList *list,  Node* node)
{
    node->next = NULL;
    node->prev = NULL;
    // 노드가 비어있음
    if(isEmpty_linkedList(list)){
        list->tail = node;
    }
    // 노드가 하나 이상 있음
    else {
        list->head->prev = node;
        node->next = list->head;
    }
    list->head = node;
    list->size++;
}

Node *peek_back_linkedList(LinkedList *list)
{
    return list->tail;
}

Node *peek_front_linkedList(LinkedList *list)
{
    return list->head;
}

void printList_linkedList(LinkedList *list)
{
    if(isEmpty_linkedList(list)) return;

    Node* present = list->head;

    int iter = 0;

    while(present != NULL){
        printf("%d\n", iter);
        present = present->next;
        iter++;
    }
}
