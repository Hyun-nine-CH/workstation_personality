
typedef struct node {
    struct node* next;
    struct node* prev;
} Node;

typedef struct linkedList {
    Node* head;
    Node* tail;
    int size;
} LinkedList;

extern void initialize_linkedList(LinkedList* list);
extern void clear_linkedList(LinkedList*);
extern int getSize_linkedList(LinkedList*);
extern int isEmpty_linkedList(LinkedList*);
extern void pop_back_linkedList(LinkedList*);
extern void pop_front_linkedList(LinkedList*);
extern void push_back_linkedList(LinkedList*, Node* node);
extern void push_front_linkedList(LinkedList*, Node* node);
extern Node* peek_back_linkedList(LinkedList*);
extern Node* peek_front_linkedList(LinkedList*);

extern void printList(LinkedList* list);