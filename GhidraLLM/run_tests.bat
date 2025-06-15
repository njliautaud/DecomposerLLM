@echo off
setlocal

echo Running Java tests...
call gradlew test

echo.
echo Running Python tests...
cd src\main\python
pip install -r requirements-test.txt
pytest

endlocal 