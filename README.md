# bitopt

bitopt is a plugin for IDA that adds optimization passes
for ROL, ROR and byteswap intrinsics.

## Installation

IDA 9.0 and newer versions:

- Install using `hcli` by running:

    ```sh
    hcli plugin install bitopt
    ```

- Or clone this repository to your IDA plugins directory

Older versions of IDA:

- Copy the contents of this repository's `/plugins/` directory
to your IDA plugins directory

## Examples

Without plugin:

```c
sub_2DA800D86A0(a4, v13, (v13 + 4), v14, v16 + 32);
v17 = ~__ROL8__(0x204E07DC0BB6B0EDLL, 47) ^ 0xD06919840FFC5DC8LL;
if ( v17 == 1747964274 )
{
    // ...
}
v18 = _byteswap_uint64(__ROR8__(v17 ^ 0x64C0765CF3EDAFECLL, 44));
if ( v18 == 303916599 )
{
    // ...
}
v19 = *(a3 + _byteswap_uint64(__ROR8__(v18, 54)));
v20 = _byteswap_uint64(0xF0F999A4FA7F0000LL);
if ( v20 == 1879457394 )
{
    // ...
}
v21 = v20();
v22 = (*(**v10 + 56LL))() + 32;
```

With plugin:

```c
sub_2DA800D86A0(a4, v13, (v13 + 4), v14, v16 + 32);
v17 = *(a3 + 1736);
v18 = MEMORY[0x7FFAA499F9F0]();
v19 = (*(**v10 + 56LL))() + 32;
```
