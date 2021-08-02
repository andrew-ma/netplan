# Development

## Building Distribution Files on Windows
```
make_pypi
```
A source distribution (".tar.gz") and a wheel distribution (".whl") will be generated in the *dist/* folder


## Installing Distribution Files
> Windows: substitute python3 with python

Source Distribution
```
python3 -m pip install {file.tar.gz}
```

Wheel Distribution
```
python3 -m pip install {file.whl}
```