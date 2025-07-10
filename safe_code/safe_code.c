#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h> // 包含limits.h以使用INT_MAX

#define BUFFER_SIZE 256

// 安全的字符串复制函数
void safe_strcpy(char *dest, const char *src) {
    strncpy(dest, src, BUFFER_SIZE - 1);
    dest[BUFFER_SIZE - 1] = '\0'; // 确保字符串以null结尾
}

// 安全的整数加法
int safe_add(int a, int b) {
    if (a > INT_MAX - b) { // 使用INT_MAX检查溢出
        return -1; // 或者其他错误处理
    }
    return a + b;
}

// 释放内存并设置为NULL
void safe_free_and_set_null(void **ptr) {
    if (*ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}

// 检查路径遍历攻击的安全路径函数
char *get_safe_path(const char *input) {
    if (strstr(input, "../")) { // 检查路径遍历攻击
        return NULL;
    }
    return strdup(input); // 安全的字符串复制
}

// 使用fgets代替gets的安全输入函数
void safe_gets(char *buffer, int size) {
    fgets(buffer, size, stdin);
    buffer[size - 1] = '\0'; // 去掉换行符
}

// 安全的内存拷贝函数
void safe_memcpy(void *dest, const void *src, size_t size) {
    memcpy(dest, src, size * sizeof(*src)); // 正确计算大小
}

// 类型安全的atoi函数
size_t safe_atoi(const char *str) {
    if (strspn(str, "0123456789") == strlen(str)) { // 正确使用strspn
        return atoi(str);
    }
    return 0; // 或其他错误处理
}

// 使用snprintf代替printf的安全打印函数
void safe_printf(char *buffer, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, size, format, args);
    va_end(args);
}

// 安全的字符串拷贝函数，避免越界读取
void safe_strncpy(char *dest, const char *src, size_t n, size_t size_of_dest) {
    if (n > size_of_dest - 1) {
        n = size_of_dest - 1;
    }
    strncpy(dest, src, n);
    dest[n] = '\0';
}

// 在解引用前检查空指针
void safe_dereference(int **ptr) {
    if (*ptr) {
        (**ptr)++;
    }
}

// 避免命令注入的安全system函数
void safe_system(const char *cmd) {
    if (strstr(cmd, ";")) { // 检查命令注入
        return;
    }
    system(cmd);
}

int main() {
    char buffer[BUFFER_SIZE];
    int a = 10;
    int b = 20;
    
    // 使用安全函数的示例
    safe_strcpy(buffer, "Hello, World!");
    printf("%s\n", buffer);
    
    int sum = safe_add(a, b);
    printf("Sum: %d\n", sum);
    
    safe_gets(buffer, BUFFER_SIZE);
    printf("Input: %s\n", buffer);
    
    safe_printf(buffer, BUFFER_SIZE, "Formatted: %s", "test");
    printf("%s\n", buffer);
    
    safe_memcpy(buffer, "memcpy test", strlen("memcpy test") + 1);
    printf("%s\n", buffer);
    
    printf("Safe atoi: %zu\n", safe_atoi("1234"));
    
    char *path = get_safe_path("../../etc/passwd");
    if (path) {
        printf("Safe path: %s\n", path);
        free(path);
    } else {
        printf("Unsafe path input detected\n");
    }
    
    int *ptr = malloc(sizeof(int));
    *ptr = 5;
    safe_dereference(&ptr);
    printf("Dereferenced value: %d\n", *ptr);
    free(ptr);
    
    safe_system("echo Safe execution");

    return 0;
}