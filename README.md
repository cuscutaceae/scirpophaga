## scirpophaga

泥嚎！scirpophaga是一个通过模拟运行的自动化提取工具，是一个用于提取生成用于某引诱接口端点中的某个参数所需的一个常量的实验性工具，用于[chilo](https://github.com/cuscutaceae/chilo)

scirpophaga的细节请见[cuscuta的草稿 - 5](https://blog.nofyso.cc/2026/05/29/cuscuta-5/)

### 使用

它的使用非常简单，只要将文件路径作为第一个参数传入即可

#### 使用预编译可执行文件

直接执行即可

```shell
./scirpophaga /path/to/the/nofy.so
```

#### 使用cargo

当然啦，自己编译也不是不行……

```shell
git clone https://github.com/cuscutaceae/scirpophaga
cd scirpophaga
cargo run /path/to/the/nofy.so
```