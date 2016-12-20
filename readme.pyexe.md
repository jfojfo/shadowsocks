### 如何打包成windows exe文件

1. windows上安装python、easyinstall、pip
2. pip install py2exe
3. 修改shadowsocks/local.py，注释掉包含`__file__`的行
4. 运行python py2exe_setup.py py2exe
5. 在生成的dist目录中添加libeay32.dll和config.json

