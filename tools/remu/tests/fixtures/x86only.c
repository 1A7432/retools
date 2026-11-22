int __attribute__((stdcall)) sub_std(int a, int b) { return a - b; }
int __attribute__((fastcall)) fast3(int a, int b, int c) { return a * 100 + b * 10 + c; }
int __attribute__((thiscall)) this2(int *self, int b) { return *self * 10 + b; }
