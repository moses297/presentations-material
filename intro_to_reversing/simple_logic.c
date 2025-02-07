#include <stdio.h>

int main() {
    int input;
    
    printf("Enter 1 or 2: ");
    scanf("%d", &input);

    if (input == 1) {
        printf("Fail\n");
    } else if (input == 2) {
        printf("Success\n");
    } else {
        printf("Invalid input\n");
    }

    return 0;
}

