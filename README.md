# Compiler Idioms

During the optimization phase, compilers often substitute high-level arithmetic operations with constant operands
resulting in faster but far less readable code.

`compiler_idioms` is a Python package, which finds such patterns in binaries and reconstructs the original arithmetic operations 
and constants. It is used for instance to improve the output of the [dewolf](https://github.com/fkie-cad/dewolf) decompiler.

Example input:
```
00000827  uint64_t func_17(int32_t arg1)

00000827  55                 push    rbp {__saved_rbp}
00000828  4889e5             mov     rbp, rsp {__saved_rbp}
0000082b  897dec             mov     dword [rbp-0x14 {var_1c}], edi
0000082e  8b45ec             mov     eax, dword [rbp-0x14 {var_1c}]
00000831  4863d0             movsxd  rdx, eax
00000834  4869d279787878     imul    rdx, rdx, 0x78787879
0000083b  48c1ea20           shr     rdx, 0x20
0000083f  c1fa03             sar     edx, 0x3
00000842  c1f81f             sar     eax, 0x1f
00000845  29c2               sub     edx, eax
00000847  89d0               mov     eax, edx
00000849  8945fc             mov     dword [rbp-0x4 {var_c}], eax
0000084c  8b45fc             mov     eax, dword [rbp-0x4 {var_c}]
0000084f  5d                 pop     rbp {__saved_rbp}
00000850  c3                 retn     {__return_addr}

```

`dewolf` output without matching compiler idioms:
```c
unsigned long func_17(int arg1) {
    return (unsigned int)(((arg1 * 0x78787879 >> 32L & 0xffffffff) >> 3) - (arg1 >> 31));
}
```
Same output using the `compiler_idioms` package:
```c
unsigned long func_17(int arg1) {
    return (unsigned int)(arg1 / 17);
}
```

See the publication [PIdARCI: Using Assembly Instruction Patterns to Identify, Annotate, and Revert Compiler Idioms](https://ieeexplore.ieee.org/document/9647781) 
for more background information and details about the approach and the pattern matching.

## Installation

`compiler_idioms` can be installed via `pip`. We recommend using a virtual environment.

```bash
pip install git+https://github.com/fkie-cad/dewolf-idioms.git
```
or
```bash
git clone https://github.com/fkie-cad/dewolf-idioms.git
pip install dewolf-idioms
```

## Usage

```python
from compiler_idioms.matcher import Matcher

# to find matches in whole binary
matches = Matcher().find_idioms_in_file(PATH_TO_BINARY) 

# to find idioms only in certain disassembly function
function_matches = Matcher().find_idioms_in_function(PATH_TO_BINARY, FUNC_ADDRESS)
```
The result is a list of `Match` objects containing `addresses` where the idiom was matched, the original arithmetic 
operation and the original constant along with some additional information.
```
ic| matches: [Match(address=2097,
                    ...
                    operation='division',
                    operand='eax',
                    constant=17,
                    ...
                    addresses=[2097, 2100, 2107, 2111, 2114, 2117, 2119])]

```
