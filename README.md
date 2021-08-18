# go-smash
Obfuscate go binaries. 混淆 go 二进制文件中的函数名  

## Usage  
```console
usage: go-smash.py [-h] [-b BINARY_PATH] [-o OUT_PATH] [-n] [-k KEYWORDS [KEYWORDS ...]]

go-smash.py -- Obfuscate go binaries

optional arguments:
  -h, --help            show this help message and exit
  -b BINARY_PATH, --binary_path BINARY_PATH
                        path to the binary that you want to obfuscate
  -o OUT_PATH, --out_path OUT_PATH
                        path to obfuscated binary
  -n, --no-log          no log
  -k KEYWORDS [KEYWORDS ...], --keywords KEYWORDS [KEYWORDS ...]
                        specify the keywords , functions with these keywords in their names will be obfuscated
```

## Example  
混淆 ez_CM.exe 中所有包含 main github runtime 关键字的函数名
```console
python go-smash.py -k main github runtime -b ezCM.exe -o ezCM_smashed.exe -n
```
混淆前：  
![](https://github.com/v0id-re/go-smash/blob/main/pic/before.png)  

混淆后：  
![](https://github.com/v0id-re/go-smash/blob/main/pic/after.png)


