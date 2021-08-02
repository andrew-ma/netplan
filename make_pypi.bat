@echo off
set MY_PYTHON=python
set SKIP_GENERATE_AUTHORS=1
set SKIP_WRITE_GIT_CHANGELOG=1

call helper_scripts\delete_folders.bat build dist venv .eggs __pycache__

call helper_scripts\clean_env.bat

%MY_PYTHON% -m pip install --upgrade pip

%MY_PYTHON% -m pip install wheel setuptools
%MY_PYTHON% -m pip install -r requirements.txt

%MY_PYTHON% setup.py sdist bdist_wheel


:: Delete folders except for dist
call helper_scripts\delete_folders.bat build .eggs __pycache__

echo Done!

:: Deactivate the venv
deactivate
