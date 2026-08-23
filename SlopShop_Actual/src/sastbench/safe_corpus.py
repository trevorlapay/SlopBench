"""Safe function generator for mixing clean code into vulnerability benchmarks.

Generates simple, genuinely safe C/C++ functions that agents must correctly
identify as non-vulnerable. Functions use proper bounds checking, null guards,
and safe patterns — no CWE footprints.
"""

from __future__ import annotations

import random
from typing import Any

from sastbench.models import TestCase

# ---------------------------------------------------------------------------
# Template functions — each is a (code_template, description) pair.
# Templates use {var} placeholders that get varied per instantiation.
# ---------------------------------------------------------------------------

_TEMPLATES: list[tuple[str, str]] = [
    # 1 — Safe bounded string copy
    (
        """\
#include <string.h>
#include <stddef.h>

void {fn}(char *dst, size_t dst_size, const char *src) {{
    if (dst == NULL || src == NULL || dst_size == 0) {{
        return;
    }}
    size_t src_len = strlen(src);
    size_t copy_len = src_len < dst_size - 1 ? src_len : dst_size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\\0';
}}
""",
        "safe_string_copy",
    ),
    # 2 — Array sum with length parameter
    (
        """\
#include <stddef.h>

long {fn}(const int *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} == 0) {{
        return 0;
    }}
    long total = 0;
    for (size_t i = 0; i < {len_var}; i++) {{
        total += arr[i];
    }}
    return total;
}}
""",
        "array_sum",
    ),
    # 3 — Binary search
    (
        """\
#include <stddef.h>

int {fn}(const int *arr, size_t {len_var}, int target) {{
    if (arr == NULL || {len_var} == 0) {{
        return -1;
    }}
    size_t lo = 0;
    size_t hi = {len_var} - 1;
    while (lo <= hi) {{
        size_t mid = lo + (hi - lo) / 2;
        if (arr[mid] == target) {{
            return (int)mid;
        }} else if (arr[mid] < target) {{
            lo = mid + 1;
        }} else {{
            if (mid == 0) break;
            hi = mid - 1;
        }}
    }}
    return -1;
}}
""",
        "binary_search",
    ),
    # 4 — Safe integer addition with overflow check
    (
        """\
#include <stdbool.h>
#include <limits.h>

bool {fn}(int a, int b, int *result) {{
    if (result == NULL) {{
        return false;
    }}
    if ((b > 0 && a > INT_MAX - b) || (b < 0 && a < INT_MIN - b)) {{
        return false;
    }}
    *result = a + b;
    return true;
}}
""",
        "safe_add",
    ),
    # 5 — Safe integer multiplication with overflow check
    (
        """\
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>

bool {fn}(int a, int b, int *result) {{
    if (result == NULL) {{
        return false;
    }}
    if (a == 0 || b == 0) {{
        *result = 0;
        return true;
    }}
    if (a > 0 && b > 0 && a > INT_MAX / b) return false;
    if (a > 0 && b < 0 && b < INT_MIN / a) return false;
    if (a < 0 && b > 0 && a < INT_MIN / b) return false;
    if (a < 0 && b < 0 && a < INT_MAX / b) return false;
    *result = a * b;
    return true;
}}
""",
        "safe_multiply",
    ),
    # 6 — Max value in array
    (
        """\
#include <stddef.h>
#include <limits.h>

int {fn}(const int *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} == 0) {{
        return INT_MIN;
    }}
    int max_val = arr[0];
    for (size_t i = 1; i < {len_var}; i++) {{
        if (arr[i] > max_val) {{
            max_val = arr[i];
        }}
    }}
    return max_val;
}}
""",
        "array_max",
    ),
    # 7 — Min value in array
    (
        """\
#include <stddef.h>
#include <limits.h>

int {fn}(const int *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} == 0) {{
        return INT_MAX;
    }}
    int min_val = arr[0];
    for (size_t i = 1; i < {len_var}; i++) {{
        if (arr[i] < min_val) {{
            min_val = arr[i];
        }}
    }}
    return min_val;
}}
""",
        "array_min",
    ),
    # 8 — Swap two integers
    (
        """\
void {fn}(int *a, int *b) {{
    if (a == NULL || b == NULL || a == b) {{
        return;
    }}
    int temp = *a;
    *a = *b;
    *b = temp;
}}
""",
        "swap_ints",
    ),
    # 9 — Count occurrences in array
    (
        """\
#include <stddef.h>

size_t {fn}(const int *arr, size_t {len_var}, int target) {{
    if (arr == NULL || {len_var} == 0) {{
        return 0;
    }}
    size_t count = 0;
    for (size_t i = 0; i < {len_var}; i++) {{
        if (arr[i] == target) {{
            count++;
        }}
    }}
    return count;
}}
""",
        "count_occurrences",
    ),
    # 10 — Reverse array in place
    (
        """\
#include <stddef.h>

void {fn}(int *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} <= 1) {{
        return;
    }}
    size_t lo = 0;
    size_t hi = {len_var} - 1;
    while (lo < hi) {{
        int temp = arr[lo];
        arr[lo] = arr[hi];
        arr[hi] = temp;
        lo++;
        hi--;
    }}
}}
""",
        "reverse_array",
    ),
    # 11 — Safe absolute value
    (
        """\
#include <limits.h>

int {fn}(int value) {{
    if (value == INT_MIN) {{
        return INT_MAX;
    }}
    return value < 0 ? -value : value;
}}
""",
        "safe_abs",
    ),
    # 12 — GCD (Euclidean algorithm)
    (
        """\
int {fn}(int a, int b) {{
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    while (b != 0) {{
        int temp = b;
        b = a % b;
        a = temp;
    }}
    return a;
}}
""",
        "gcd",
    ),
    # 13 — Power function (integer)
    (
        """\
#include <stdbool.h>

bool {fn}(int base, unsigned int exp, long long *result) {{
    if (result == NULL) {{
        return false;
    }}
    long long res = 1;
    long long b = base;
    while (exp > 0) {{
        if (exp & 1) {{
            res *= b;
        }}
        b *= b;
        exp >>= 1;
    }}
    *result = res;
    return true;
}}
""",
        "safe_power",
    ),
    # 14 — Is palindrome (bounded string)
    (
        """\
#include <stdbool.h>
#include <string.h>
#include <stddef.h>

bool {fn}(const char *str) {{
    if (str == NULL) {{
        return false;
    }}
    size_t len = strlen(str);
    if (len <= 1) {{
        return true;
    }}
    size_t lo = 0;
    size_t hi = len - 1;
    while (lo < hi) {{
        if (str[lo] != str[hi]) {{
            return false;
        }}
        lo++;
        hi--;
    }}
    return true;
}}
""",
        "is_palindrome",
    ),
    # 15 — Safe memset wrapper
    (
        """\
#include <string.h>
#include <stddef.h>

void {fn}(void *ptr, int value, size_t size) {{
    if (ptr == NULL || size == 0) {{
        return;
    }}
    memset(ptr, value, size);
}}
""",
        "safe_memset",
    ),
    # 16 — Clamp value to range
    (
        """\
int {fn}(int value, int min_val, int max_val) {{
    if (min_val > max_val) {{
        int temp = min_val;
        min_val = max_val;
        max_val = temp;
    }}
    if (value < min_val) return min_val;
    if (value > max_val) return max_val;
    return value;
}}
""",
        "clamp",
    ),
    # 17 — String length with max bound
    (
        """\
#include <stddef.h>

size_t {fn}(const char *str, size_t max_len) {{
    if (str == NULL) {{
        return 0;
    }}
    size_t len = 0;
    while (len < max_len && str[len] != '\\0') {{
        len++;
    }}
    return len;
}}
""",
        "bounded_strlen",
    ),
    # 18 — Matrix element accessor with bounds check
    (
        """\
#include <stdbool.h>
#include <stddef.h>

bool {fn}(const int *matrix, size_t rows, size_t cols,
                  size_t row, size_t col, int *out) {{
    if (matrix == NULL || out == NULL) {{
        return false;
    }}
    if (row >= rows || col >= cols) {{
        return false;
    }}
    *out = matrix[row * cols + col];
    return true;
}}
""",
        "matrix_get",
    ),
    # 19 — Insertion sort
    (
        """\
#include <stddef.h>

void {fn}(int *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} <= 1) {{
        return;
    }}
    for (size_t i = 1; i < {len_var}; i++) {{
        int key = arr[i];
        size_t j = i;
        while (j > 0 && arr[j - 1] > key) {{
            arr[j] = arr[j - 1];
            j--;
        }}
        arr[j] = key;
    }}
}}
""",
        "insertion_sort",
    ),
    # 20 — Bubble sort
    (
        """\
#include <stdbool.h>
#include <stddef.h>

void {fn}(int *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} <= 1) {{
        return;
    }}
    bool swapped;
    for (size_t i = 0; i < {len_var} - 1; i++) {{
        swapped = false;
        for (size_t j = 0; j < {len_var} - 1 - i; j++) {{
            if (arr[j] > arr[j + 1]) {{
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
                swapped = true;
            }}
        }}
        if (!swapped) break;
    }}
}}
""",
        "bubble_sort",
    ),
    # 21 — Safe file read (returns allocated buffer)
    (
        """\
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

char *{fn}(const char *path, size_t max_size, size_t *out_len) {{
    if (path == NULL || out_len == NULL || max_size == 0) {{
        return NULL;
    }}
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {{
        return NULL;
    }}
    char *buf = (char *)malloc(max_size + 1);
    if (buf == NULL) {{
        fclose(fp);
        return NULL;
    }}
    size_t nread = fread(buf, 1, max_size, fp);
    fclose(fp);
    buf[nread] = '\\0';
    *out_len = nread;
    return buf;
}}
""",
        "safe_file_read",
    ),
    # 22 — Safe file write
    (
        """\
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

bool {fn}(const char *path, const void *data, size_t size) {{
    if (path == NULL || data == NULL || size == 0) {{
        return false;
    }}
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {{
        return false;
    }}
    size_t written = fwrite(data, 1, size, fp);
    fclose(fp);
    return written == size;
}}
""",
        "safe_file_write",
    ),
    # 23 — Linked list node count with cycle guard
    (
        """\
#include <stddef.h>

typedef struct {node_type} {{
    int data;
    struct {node_type} *next;
}} {node_type};

size_t {fn}(const {node_type} *head, size_t max_nodes) {{
    size_t count = 0;
    const {node_type} *curr = head;
    while (curr != NULL && count < max_nodes) {{
        count++;
        curr = curr->next;
    }}
    return count;
}}
""",
        "list_count",
    ),
    # 24 — Linked list search
    (
        """\
#include <stdbool.h>
#include <stddef.h>

typedef struct {node_type} {{
    int value;
    struct {node_type} *next;
}} {node_type};

bool {fn}(const {node_type} *head, int target, size_t max_depth) {{
    const {node_type} *curr = head;
    size_t depth = 0;
    while (curr != NULL && depth < max_depth) {{
        if (curr->value == target) {{
            return true;
        }}
        curr = curr->next;
        depth++;
    }}
    return false;
}}
""",
        "list_search",
    ),
    # 25 — Ring buffer write
    (
        """\
#include <stdbool.h>
#include <stddef.h>

typedef struct {{
    int *buf;
    size_t capacity;
    size_t head;
    size_t count;
}} {ring_type};

bool {fn}({ring_type} *rb, int value) {{
    if (rb == NULL || rb->buf == NULL || rb->capacity == 0) {{
        return false;
    }}
    size_t idx = (rb->head + rb->count) % rb->capacity;
    rb->buf[idx] = value;
    if (rb->count < rb->capacity) {{
        rb->count++;
    }} else {{
        rb->head = (rb->head + 1) % rb->capacity;
    }}
    return true;
}}
""",
        "ring_buffer_write",
    ),
    # 26 — Average of array (floating point)
    (
        """\
#include <stddef.h>

double {fn}(const double *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} == 0) {{
        return 0.0;
    }}
    double sum = 0.0;
    for (size_t i = 0; i < {len_var}; i++) {{
        sum += arr[i];
    }}
    return sum / (double){len_var};
}}
""",
        "array_average",
    ),
    # 27 — Dot product
    (
        """\
#include <stddef.h>

double {fn}(const double *a, const double *b, size_t {len_var}) {{
    if (a == NULL || b == NULL || {len_var} == 0) {{
        return 0.0;
    }}
    double result = 0.0;
    for (size_t i = 0; i < {len_var}; i++) {{
        result += a[i] * b[i];
    }}
    return result;
}}
""",
        "dot_product",
    ),
    # 28 — Is sorted check
    (
        """\
#include <stdbool.h>
#include <stddef.h>

bool {fn}(const int *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} <= 1) {{
        return true;
    }}
    for (size_t i = 1; i < {len_var}; i++) {{
        if (arr[i] < arr[i - 1]) {{
            return false;
        }}
    }}
    return true;
}}
""",
        "is_sorted",
    ),
    # 29 — Safe substring extraction
    (
        """\
#include <string.h>
#include <stdbool.h>
#include <stddef.h>

bool {fn}(const char *src, size_t start, size_t sub_len,
                 char *dst, size_t dst_size) {{
    if (src == NULL || dst == NULL || dst_size == 0) {{
        return false;
    }}
    size_t src_len = strlen(src);
    if (start >= src_len) {{
        dst[0] = '\\0';
        return true;
    }}
    size_t avail = src_len - start;
    size_t copy_len = sub_len < avail ? sub_len : avail;
    if (copy_len >= dst_size) {{
        copy_len = dst_size - 1;
    }}
    memcpy(dst, src + start, copy_len);
    dst[copy_len] = '\\0';
    return true;
}}
""",
        "safe_substring",
    ),
    # 30 — Fibonacci (iterative, safe)
    (
        """\
#include <stdbool.h>

bool {fn}(unsigned int n, unsigned long long *result) {{
    if (result == NULL) {{
        return false;
    }}
    if (n == 0) {{ *result = 0; return true; }}
    if (n == 1) {{ *result = 1; return true; }}
    unsigned long long prev = 0, curr = 1;
    for (unsigned int i = 2; i <= n; i++) {{
        unsigned long long next = prev + curr;
        if (next < curr) {{
            return false;  /* overflow */
        }}
        prev = curr;
        curr = next;
    }}
    *result = curr;
    return true;
}}
""",
        "fibonacci",
    ),
    # 31 — Safe array copy
    (
        """\
#include <string.h>
#include <stdbool.h>
#include <stddef.h>

bool {fn}(const int *src, size_t src_len, int *dst, size_t dst_cap) {{
    if (src == NULL || dst == NULL) {{
        return false;
    }}
    size_t copy_count = src_len < dst_cap ? src_len : dst_cap;
    memcpy(dst, src, copy_count * sizeof(int));
    return true;
}}
""",
        "safe_array_copy",
    ),
    # 32 — Stack push with bounds
    (
        """\
#include <stdbool.h>
#include <stddef.h>

typedef struct {{
    int *data;
    size_t capacity;
    size_t top;
}} {stack_type};

bool {fn}({stack_type} *s, int value) {{
    if (s == NULL || s->data == NULL) {{
        return false;
    }}
    if (s->top >= s->capacity) {{
        return false;
    }}
    s->data[s->top] = value;
    s->top++;
    return true;
}}
""",
        "stack_push",
    ),
    # 33 — Stack pop with bounds
    (
        """\
#include <stdbool.h>
#include <stddef.h>

typedef struct {{
    int *data;
    size_t capacity;
    size_t top;
}} {stack_type};

bool {fn}({stack_type} *s, int *out) {{
    if (s == NULL || s->data == NULL || out == NULL) {{
        return false;
    }}
    if (s->top == 0) {{
        return false;
    }}
    s->top--;
    *out = s->data[s->top];
    return true;
}}
""",
        "stack_pop",
    ),
    # 34 — Hash function (djb2)
    (
        """\
#include <stddef.h>

unsigned long {fn}(const char *str, size_t max_len) {{
    if (str == NULL) {{
        return 0;
    }}
    unsigned long hash = 5381;
    size_t i = 0;
    while (i < max_len && str[i] != '\\0') {{
        hash = ((hash << 5) + hash) + (unsigned char)str[i];
        i++;
    }}
    return hash;
}}
""",
        "djb2_hash",
    ),
    # 35 — Selection sort
    (
        """\
#include <stddef.h>

void {fn}(int *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} <= 1) {{
        return;
    }}
    for (size_t i = 0; i < {len_var} - 1; i++) {{
        size_t min_idx = i;
        for (size_t j = i + 1; j < {len_var}; j++) {{
            if (arr[j] < arr[min_idx]) {{
                min_idx = j;
            }}
        }}
        if (min_idx != i) {{
            int temp = arr[i];
            arr[i] = arr[min_idx];
            arr[min_idx] = temp;
        }}
    }}
}}
""",
        "selection_sort",
    ),
    # 36 — Two-sum in sorted array
    (
        """\
#include <stdbool.h>
#include <stddef.h>

bool {fn}(const int *arr, size_t {len_var}, int target,
                   size_t *idx_a, size_t *idx_b) {{
    if (arr == NULL || {len_var} < 2 || idx_a == NULL || idx_b == NULL) {{
        return false;
    }}
    size_t lo = 0, hi = {len_var} - 1;
    while (lo < hi) {{
        int sum = arr[lo] + arr[hi];
        if (sum == target) {{
            *idx_a = lo;
            *idx_b = hi;
            return true;
        }} else if (sum < target) {{
            lo++;
        }} else {{
            hi--;
        }}
    }}
    return false;
}}
""",
        "two_sum_sorted",
    ),
    # 37 — Safe bounded memcmp wrapper
    (
        """\
#include <string.h>
#include <stddef.h>

int {fn}(const void *a, const void *b, size_t size) {{
    if (a == NULL || b == NULL || size == 0) {{
        return 0;
    }}
    return memcmp(a, b, size);
}}
""",
        "safe_memcmp",
    ),
    # 38 — Char frequency counter
    (
        """\
#include <stddef.h>

void {fn}(const char *str, size_t max_len, unsigned int freq[256]) {{
    if (str == NULL || freq == NULL) {{
        return;
    }}
    for (int i = 0; i < 256; i++) {{
        freq[i] = 0;
    }}
    for (size_t i = 0; i < max_len && str[i] != '\\0'; i++) {{
        freq[(unsigned char)str[i]]++;
    }}
}}
""",
        "char_frequency",
    ),
    # 39 — Median of three
    (
        """\
int {fn}(int a, int b, int c) {{
    if ((a >= b && a <= c) || (a <= b && a >= c)) return a;
    if ((b >= a && b <= c) || (b <= a && b >= c)) return b;
    return c;
}}
""",
        "median_of_three",
    ),
    # 40 — Safe division
    (
        """\
#include <stdbool.h>
#include <limits.h>

bool {fn}(int a, int b, int *result) {{
    if (result == NULL || b == 0) {{
        return false;
    }}
    if (a == INT_MIN && b == -1) {{
        return false;
    }}
    *result = a / b;
    return true;
}}
""",
        "safe_divide",
    ),
    # 41 — Array contains
    (
        """\
#include <stdbool.h>
#include <stddef.h>

bool {fn}(const int *arr, size_t {len_var}, int value) {{
    if (arr == NULL) {{
        return false;
    }}
    for (size_t i = 0; i < {len_var}; i++) {{
        if (arr[i] == value) {{
            return true;
        }}
    }}
    return false;
}}
""",
        "array_contains",
    ),
    # 42 — Rotate array left by k
    (
        """\
#include <stddef.h>

static void _reverse_range(int *arr, size_t lo, size_t hi) {{
    while (lo < hi) {{
        int temp = arr[lo];
        arr[lo] = arr[hi];
        arr[hi] = temp;
        lo++;
        hi--;
    }}
}}

void {fn}(int *arr, size_t {len_var}, size_t k) {{
    if (arr == NULL || {len_var} <= 1) {{
        return;
    }}
    k = k % {len_var};
    if (k == 0) return;
    _reverse_range(arr, 0, k - 1);
    _reverse_range(arr, k, {len_var} - 1);
    _reverse_range(arr, 0, {len_var} - 1);
}}
""",
        "rotate_left",
    ),
    # 43 — String to uppercase (bounded)
    (
        """\
#include <stddef.h>

void {fn}(char *str, size_t max_len) {{
    if (str == NULL) {{
        return;
    }}
    for (size_t i = 0; i < max_len && str[i] != '\\0'; i++) {{
        if (str[i] >= 'a' && str[i] <= 'z') {{
            str[i] = str[i] - 'a' + 'A';
        }}
    }}
}}
""",
        "to_upper",
    ),
    # 44 — String to lowercase (bounded)
    (
        """\
#include <stddef.h>

void {fn}(char *str, size_t max_len) {{
    if (str == NULL) {{
        return;
    }}
    for (size_t i = 0; i < max_len && str[i] != '\\0'; i++) {{
        if (str[i] >= 'A' && str[i] <= 'Z') {{
            str[i] = str[i] - 'A' + 'a';
        }}
    }}
}}
""",
        "to_lower",
    ),
    # 45 — Count digits in string
    (
        """\
#include <stddef.h>

size_t {fn}(const char *str, size_t max_len) {{
    if (str == NULL) {{
        return 0;
    }}
    size_t count = 0;
    for (size_t i = 0; i < max_len && str[i] != '\\0'; i++) {{
        if (str[i] >= '0' && str[i] <= '9') {{
            count++;
        }}
    }}
    return count;
}}
""",
        "count_digits",
    ),
    # 46 — Merge two sorted arrays
    (
        """\
#include <stdbool.h>
#include <stddef.h>

bool {fn}(const int *a, size_t a_len, const int *b, size_t b_len,
                    int *out, size_t out_cap) {{
    if ((a == NULL && a_len > 0) || (b == NULL && b_len > 0) || out == NULL) {{
        return false;
    }}
    if (a_len + b_len > out_cap) {{
        return false;
    }}
    size_t i = 0, j = 0, k = 0;
    while (i < a_len && j < b_len) {{
        if (a[i] <= b[j]) {{
            out[k++] = a[i++];
        }} else {{
            out[k++] = b[j++];
        }}
    }}
    while (i < a_len) out[k++] = a[i++];
    while (j < b_len) out[k++] = b[j++];
    return true;
}}
""",
        "merge_sorted",
    ),
    # 47 — Remove duplicates from sorted array
    (
        """\
#include <stddef.h>

size_t {fn}(int *arr, size_t {len_var}) {{
    if (arr == NULL || {len_var} == 0) {{
        return 0;
    }}
    size_t write = 1;
    for (size_t read = 1; read < {len_var}; read++) {{
        if (arr[read] != arr[read - 1]) {{
            arr[write] = arr[read];
            write++;
        }}
    }}
    return write;
}}
""",
        "remove_duplicates",
    ),
    # 48 — Matrix transpose (with bounds)
    (
        """\
#include <stdbool.h>
#include <stddef.h>

bool {fn}(const int *src, size_t rows, size_t cols,
                      int *dst, size_t dst_cap) {{
    if (src == NULL || dst == NULL) {{
        return false;
    }}
    if (rows * cols > dst_cap) {{
        return false;
    }}
    for (size_t r = 0; r < rows; r++) {{
        for (size_t c = 0; c < cols; c++) {{
            dst[c * rows + r] = src[r * cols + c];
        }}
    }}
    return true;
}}
""",
        "matrix_transpose",
    ),
    # 49 — Safe string compare (bounded)
    (
        """\
#include <stddef.h>

int {fn}(const char *a, const char *b, size_t max_len) {{
    if (a == NULL && b == NULL) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;
    for (size_t i = 0; i < max_len; i++) {{
        if (a[i] != b[i]) {{
            return (unsigned char)a[i] - (unsigned char)b[i];
        }}
        if (a[i] == '\\0') break;
    }}
    return 0;
}}
""",
        "safe_strcmp",
    ),
    # 50 — Bit count (popcount)
    (
        """\
unsigned int {fn}(unsigned int value) {{
    unsigned int count = 0;
    while (value) {{
        count += value & 1;
        value >>= 1;
    }}
    return count;
}}
""",
        "popcount",
    ),
    # 51 — Safe realloc wrapper
    (
        """\
#include <stdlib.h>
#include <stddef.h>

void *{fn}(void *ptr, size_t new_size) {{
    if (new_size == 0) {{
        free(ptr);
        return NULL;
    }}
    void *new_ptr = realloc(ptr, new_size);
    if (new_ptr == NULL) {{
        /* Original pointer still valid; caller must free it */
        return NULL;
    }}
    return new_ptr;
}}
""",
        "safe_realloc",
    ),
    # 52 — Linear interpolation
    (
        """\
double {fn}(double a, double b, double t) {{
    if (t <= 0.0) return a;
    if (t >= 1.0) return b;
    return a + (b - a) * t;
}}
""",
        "lerp",
    ),
    # 53 — Array fill
    (
        """\
#include <stddef.h>

void {fn}(int *arr, size_t {len_var}, int value) {{
    if (arr == NULL) {{
        return;
    }}
    for (size_t i = 0; i < {len_var}; i++) {{
        arr[i] = value;
    }}
}}
""",
        "array_fill",
    ),
    # 54 — Safe string concatenation
    (
        """\
#include <string.h>
#include <stdbool.h>
#include <stddef.h>

bool {fn}(char *dst, size_t dst_size, const char *src) {{
    if (dst == NULL || src == NULL || dst_size == 0) {{
        return false;
    }}
    size_t dst_len = strlen(dst);
    if (dst_len >= dst_size - 1) {{
        return false;
    }}
    size_t remaining = dst_size - dst_len - 1;
    size_t src_len = strlen(src);
    size_t copy_len = src_len < remaining ? src_len : remaining;
    memcpy(dst + dst_len, src, copy_len);
    dst[dst_len + copy_len] = '\\0';
    return true;
}}
""",
        "safe_strcat",
    ),
    # 55 — Is power of two
    (
        """\
#include <stdbool.h>

bool {fn}(unsigned int value) {{
    if (value == 0) {{
        return false;
    }}
    return (value & (value - 1)) == 0;
}}
""",
        "is_power_of_two",
    ),
]

# Variable name pools for instantiation variety
_FN_PREFIXES = [
    "do", "get", "set", "parse", "handle", "init", "read", "write",
    "send", "recv", "alloc", "reset", "open", "close", "flush",
    "create", "update", "convert", "encode", "decode",
]
_LEN_VARS = ["len", "count", "size", "num_elements", "n", "length"]
_NODE_TYPES = ["Node", "ListNode", "SLNode", "Entry", "Item"]
_RING_TYPES = ["RingBuf", "CircBuf", "RingBuffer", "CircularQueue"]
_STACK_TYPES = ["IntStack", "Stack", "ArrayStack", "BoundedStack"]


def generate_safe_functions(
    count: int,
    seed: int = 42,
    *,
    cpp_ratio: float = 0.0,
    workspace_name: str = "",
) -> list[TestCase]:
    """Generate safe C/C++ functions as TestCase objects.

    Each function is a complete, compilable C function with proper null guards,
    bounds checking, and no CWE patterns.

    Args:
        count: Number of safe functions to generate.
        seed: Random seed for reproducible variation.
        cpp_ratio: Fraction of files to emit as .cpp (0.0–1.0) to match
            the benchmark's language distribution and prevent language-based
            gaming.
        workspace_name: If provided, mixed into the seed to produce unique
            safe corpora per workspace (prevents cross-workspace memorization).

    Returns:
        List of TestCase objects with is_vulnerable=False metadata.
    """
    if count <= 0:
        return []

    # Derive per-workspace seed to prevent memorization across workspaces
    if workspace_name:
        import hashlib
        derived = int(hashlib.sha256(f"{seed}:{workspace_name}".encode()).hexdigest()[:8], 16)
        rng = random.Random(derived)
    else:
        rng = random.Random(seed)
    results: list[TestCase] = []

    for i in range(count):
        template_code, desc = _TEMPLATES[i % len(_TEMPLATES)]
        prefix = rng.choice(_FN_PREFIXES)
        suffix = rng.randint(1, 9999)
        # Vary naming schemes to avoid synthetic-looking patterns
        naming_style = rng.choice(["underscore", "plain", "camel"])
        if naming_style == "underscore":
            fn_name = f"{prefix}_{suffix}"
        elif naming_style == "plain":
            fn_name = f"{prefix}{suffix}"
        else:
            fn_name = f"{prefix}{str(suffix).zfill(2)}"

        replacements: dict[str, str] = {
            "fn": fn_name,
            "len_var": rng.choice(_LEN_VARS),
            "node_type": rng.choice(_NODE_TYPES),
            "ring_type": rng.choice(_RING_TYPES),
            "stack_type": rng.choice(_STACK_TYPES),
        }

        code = template_code
        for key, val in replacements.items():
            code = code.replace("{" + key + "}", val)
        # Fix escaped braces from Python format strings — these produce
        # invalid C syntax ({{ / }}) and are a fingerprint for safe files.
        code = code.replace("{{", "{").replace("}}", "}")

        # Assign language based on cpp_ratio to match benchmark distribution
        lang = "cpp" if rng.random() < cpp_ratio else "c"
        ext = "cpp" if lang == "cpp" else "c"

        tc = TestCase(
            original_id=f"gen_{i:05d}",
            original_path=f"corpus/{fn_name}.{ext}",
            code=code,
            language=lang,
            metadata={"is_safe_injection": True},
        )
        results.append(tc)

    return results
